"""Alert processor and orchestrator (SQS -> this Lambda).

For each alert message:
  1. create a ServiceNow incident (when ServiceNow is configured) and acknowledge it
  2. retrieve matching runbooks from the Bedrock Knowledge Base
  3. let Claude (Bedrock Converse API) reason and call two tools:
       QueryTelemetry, ExecuteRemediation   (served by the tool Lambda)
  4. enforce a policy gate in code before any remediation runs
  5. resolve the ticket when verified, otherwise leave it open with notes

Errors are raised so SQS retries the message and, after the configured number of
receives, moves it to the dead-letter queue (which the Phase 6 alarm watches).
"""
import base64
import hashlib
import json
import os
import re
import traceback
import urllib.error
import urllib.request

import boto3

INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
INSTANCE_LABEL_KEYS = ("InstanceId", "instance_id", "instanceId", "instance")

MODEL_ID = os.environ.get("MODEL_ID", "")
KNOWLEDGE_BASE_ID = os.environ.get("KNOWLEDGE_BASE_ID", "")
TOOL_LAMBDA_ARN = os.environ.get("TOOL_LAMBDA_ARN", "")
SERVICENOW_SECRET_ID = os.environ.get("SERVICENOW_SECRET_ID", "")
MAX_TURNS = int(os.environ.get("MAX_TURNS", "6"))
CLOSE_CODE = os.environ.get("SERVICENOW_CLOSE_CODE", "Solved (Permanently)")
ACTION_GROUP = "OperationalTools"

# Runbook allow-list: only "low" risk runbooks run without a human.
DEFAULT_POLICY = {"AIOps-DiskCleanupWorkflow": "low"}


def load_policy():
    raw = os.environ.get("REMEDIATION_POLICY")
    if not raw:
        return dict(DEFAULT_POLICY)
    try:
        policy = json.loads(raw)
        return policy if isinstance(policy, dict) else dict(DEFAULT_POLICY)
    except json.JSONDecodeError:
        return dict(DEFAULT_POLICY)


SYSTEM_PROMPT = """You are the automated AIOps incident orchestrator. Triage and resolve the alert using approved procedures only.

Follow this sequence:
1. Read the alert and the runbook excerpts supplied by the user message.
2. Call QueryTelemetry to confirm the anomaly is still active. Use the query suggested by the runbook if there is one.
3. If a runbook names a remediation whose name starts with 'AIOps-', call ExecuteRemediation with that exact runbook_name and the alert's instance id as target_id. Never invent runbook names or instance ids.
4. If ExecuteRemediation returns status 'NotExecuted' or 'Rejected', do not retry with other names. Explain why and escalate.
5. After a successful remediation, call QueryTelemetry again to verify the anomaly cleared.
6. If QueryTelemetry returns status 'unavailable', say verification could not be performed.

Finish with a short summary (2 to 5 sentences) and then a final line that is exactly one of:
RESULT: RESOLVED   (remediation succeeded and telemetry shows the anomaly cleared; or remediation succeeded and telemetry is unavailable)
RESULT: ESCALATE   (no matching runbook, action not allowed, remediation failed, or anomaly still active)
"""

TOOL_CONFIG = {
    "tools": [
        {
            "toolSpec": {
                "name": "QueryTelemetry",
                "description": "Query live telemetry (PromQL) to check whether the alert condition is still active.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {"query": {"type": "string", "description": "PromQL expression for the anomalous metric."}},
                        "required": ["query"],
                    }
                },
            }
        },
        {
            "toolSpec": {
                "name": "ExecuteRemediation",
                "description": "Run an approved AWS Systems Manager Automation runbook (name must start with AIOps-) on one instance.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "runbook_name": {"type": "string", "description": "Automation document name, must start with AIOps-."},
                            "target_id": {"type": "string", "description": "EC2 instance id from the alert, for example i-0123456789abcdef0."},
                        },
                        "required": ["runbook_name", "target_id"],
                    }
                },
            }
        },
    ]
}

_clients = {}


def client(name):
    if name not in _clients:
        _clients[name] = boto3.client(name)
    return _clients[name]


# ---------------------------------------------------------------- alert parsing
def _instance_id(labels, alert):
    candidates = [labels.get(k) for k in INSTANCE_LABEL_KEYS] + [alert.get("instance_id")]
    for value in candidates:
        if isinstance(value, str) and INSTANCE_ID_RE.match(value):
            return value
    return None


def normalize_alert(body):
    """Accept a flat message from the receiver or a raw Grafana payload; return one alert."""
    alerts = body.get("alerts") if isinstance(body, dict) else None
    if isinstance(alerts, list) and alerts:
        firing = [a for a in alerts if isinstance(a, dict) and (a.get("status") or body.get("status") or "firing") == "firing"]
        a = (firing or alerts)[0]
        status = a.get("status") or body.get("status") or "firing"
    else:
        a = body if isinstance(body, dict) else {}
        status = a.get("status") or "firing"
    labels = a.get("labels") or {}
    annotations = a.get("annotations") or {}
    alertname = labels.get("alertname") or a.get("alertname") or "UnknownAlert"
    instance_id = _instance_id(labels, a)
    return {
        "alertname": alertname,
        "severity": str(labels.get("severity") or a.get("severity") or "critical").lower(),
        "instance_id": instance_id,
        "summary": annotations.get("summary") or annotations.get("description") or a.get("summary") or "",
        "status": status,
        "fingerprint": a.get("fingerprint")
        or hashlib.sha1(f"{alertname}|{instance_id}".encode("utf-8")).hexdigest()[:16],
        "labels": labels,
        "annotations": annotations,
    }


# ------------------------------------------------------------------- ServiceNow
def get_servicenow_credentials():
    """Return credentials, or None when ServiceNow is not configured yet."""
    if not SERVICENOW_SECRET_ID:
        return None
    secret = client("secretsmanager").get_secret_value(SecretId=SERVICENOW_SECRET_ID)
    creds = json.loads(secret["SecretString"])
    if "CHANGE_ME" in json.dumps(creds):
        print("[!] ServiceNow secret still has CHANGE_ME placeholders; running without a ticket.")
        return None
    return creds


def servicenow_request(creds, method, path, body=None):
    url = creds["instance_url"].rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    token = base64.b64encode(f"{creds['user']}:{creds['password']}".encode("utf-8")).decode("utf-8")
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8") or "{}")


def create_incident(creds, alert):
    impact_urgency = "1" if alert["severity"] == "critical" else "2"
    body = {
        "short_description": f"[AIOps] {alert['alertname']}" + (f" on {alert['instance_id']}" if alert["instance_id"] else ""),
        "description": f"Automated AIOps ingestion.\n\n{alert['summary']}\n\nAlert:\n{json.dumps(alert, indent=2)}",
        "urgency": impact_urgency,
        "impact": "2",
    }
    result = servicenow_request(creds, "POST", "/api/now/table/incident", body).get("result", {})
    return result.get("number"), result.get("sys_id")


def update_incident(creds, sys_id, fields):
    """Best-effort ticket update. Never raises, so a ticket problem cannot trigger a re-run."""
    if not creds or not sys_id:
        return
    try:
        servicenow_request(creds, "PATCH", f"/api/now/table/incident/{sys_id}", fields)
    except Exception as exc:
        print(f"[-] ServiceNow update failed: {exc}")


# ------------------------------------------------------------------ Knowledge Base
def retrieve_runbooks(alert):
    if not KNOWLEDGE_BASE_ID:
        return []
    query = f"{alert['alertname']} {alert['summary']}".strip()[:1000]
    try:
        resp = client("bedrock-agent-runtime").retrieve(
            knowledgeBaseId=KNOWLEDGE_BASE_ID,
            retrievalQuery={"text": query},
            retrievalConfiguration={"vectorSearchConfiguration": {"numberOfResults": 4}},
        )
    except Exception as exc:
        print(f"[-] Knowledge Base retrieval failed: {exc}")
        return []
    return [r["content"]["text"] for r in resp.get("retrievalResults", []) if r.get("content", {}).get("text")]


# ---------------------------------------------------------------------- policy gate
def policy_gate(runbook_name, target_id, alert):
    """Decide in code whether a remediation may run without a human."""
    policy = load_policy()
    if not runbook_name or not target_id:
        return False, "runbook_name and target_id are required"
    if not runbook_name.startswith("AIOps-"):
        return False, "runbook name must start with AIOps-"
    tier = policy.get(runbook_name)
    if tier is None:
        return False, f"{runbook_name} is not on the allow-list"
    if tier != "low":
        return False, f"{runbook_name} is risk tier '{tier}' and needs human approval"
    if not INSTANCE_ID_RE.match(target_id):
        return False, "target_id is not a valid EC2 instance id"
    if not alert.get("instance_id"):
        return False, "the alert carries no instance id, so the target cannot be verified"
    if target_id != alert["instance_id"]:
        return False, "target_id does not match the instance in the alert"
    return True, "allowed (low risk, on allow-list, target matches alert)"


# --------------------------------------------------------------------------- tools
def invoke_tool_lambda(function_name, args):
    event = {
        "messageVersion": "1.0",
        "actionGroup": ACTION_GROUP,
        "function": function_name,
        "parameters": [{"name": k, "type": "string", "value": str(v)} for k, v in (args or {}).items()],
    }
    resp = client("lambda").invoke(FunctionName=TOOL_LAMBDA_ARN, Payload=json.dumps(event).encode("utf-8"))
    payload = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        return {"status": "ToolError", "error": payload.get("errorMessage", "tool Lambda failed")}
    text = payload["response"]["functionResponse"]["responseBody"]["TEXT"]
    return json.loads(text)


def run_tool(name, args, alert, log):
    if name == "QueryTelemetry":
        result = invoke_tool_lambda(name, args)
    elif name == "ExecuteRemediation":
        allowed, reason = policy_gate(args.get("runbook_name"), args.get("target_id"), alert)
        log.append(f"policy gate: {args.get('runbook_name')} on {args.get('target_id')} -> {reason}")
        if not allowed:
            return {"status": "NotExecuted", "reason": reason}
        result = invoke_tool_lambda(name, args)
    else:
        return {"error": f"unknown tool {name}"}
    log.append(f"tool {name}({json.dumps(args)}) -> {json.dumps(result)}")
    return result


# ----------------------------------------------------------------------- orchestration
def build_user_message(alert, runbooks):
    runbook_text = "\n\n---\n\n".join(runbooks) if runbooks else "(no matching runbook was found)"
    return (
        "Alert:\n"
        f"- name: {alert['alertname']}\n"
        f"- severity: {alert['severity']}\n"
        f"- instance id: {alert['instance_id'] or 'not provided'}\n"
        f"- summary: {alert['summary'] or 'not provided'}\n\n"
        f"Runbook excerpts:\n{runbook_text}"
    )


def orchestrate(alert, runbooks):
    log = []
    messages = [{"role": "user", "content": [{"text": build_user_message(alert, runbooks)}]}]
    for _ in range(MAX_TURNS):
        resp = client("bedrock-runtime").converse(
            modelId=MODEL_ID,
            system=[{"text": SYSTEM_PROMPT}],
            messages=messages,
            toolConfig=TOOL_CONFIG,
            inferenceConfig={"maxTokens": 1024, "temperature": 0},
        )
        message = resp["output"]["message"]
        messages.append(message)
        if resp.get("stopReason") != "tool_use":
            text = "".join(block.get("text", "") for block in message["content"])
            return text, log
        results = []
        for block in message["content"]:
            if "toolUse" in block:
                use = block["toolUse"]
                out = run_tool(use["name"], use.get("input", {}), alert, log)
                results.append({"toolResult": {"toolUseId": use["toolUseId"], "content": [{"json": out}]}})
        messages.append({"role": "user", "content": results})
    return "The orchestrator reached its turn limit without finishing.\nRESULT: ESCALATE", log


def parse_result(text):
    match = re.search(r"RESULT:\s*(RESOLVED|ESCALATE)\s*$", text.strip(), re.IGNORECASE)
    return match.group(1).upper() if match else "ESCALATE"


# ---------------------------------------------------------------------------- handler
def process_record(record):
    try:
        body = json.loads(record.get("body", "{}"))
    except json.JSONDecodeError:
        body = {"alertname": "RawPayload", "summary": str(record.get("body", ""))[:500]}
    alert = normalize_alert(body)
    if str(alert["status"]).lower() == "resolved":
        print(f"[+] Skipping resolved alert {alert['alertname']}")
        return

    creds = get_servicenow_credentials()
    number, sys_id = (None, None)
    if creds:
        number, sys_id = create_incident(creds, alert)
        print(f"[+] Created incident {number}")
        update_incident(creds, sys_id, {"state": "2", "work_notes": "AIOps orchestrator acknowledged this incident and started triage."})

    runbooks = retrieve_runbooks(alert)
    text, log = orchestrate(alert, runbooks)
    outcome = parse_result(text)
    notes = f"AIOps orchestrator outcome: {outcome}\n\n{text}\n\nActions:\n" + "\n".join(f"- {line}" for line in log)
    print(notes)

    if outcome == "RESOLVED":
        update_incident(creds, sys_id, {"state": "6", "close_code": CLOSE_CODE, "close_notes": text[:1000], "work_notes": notes})
    else:
        update_incident(creds, sys_id, {"work_notes": notes + "\n\nEscalated to a human responder."})


def handler(event, context):
    failures = []
    for record in event.get("Records", []):
        try:
            process_record(record)
        except Exception:
            traceback.print_exc()
            failures.append({"itemIdentifier": record.get("messageId")})
    return {"batchItemFailures": failures}
