"""Tool Lambda: telemetry check and remediation.

Keeps the Bedrock action-group event/response format, so it works unchanged with
the orchestrator Lambda (which builds the same event) or with an agent platform.
"""
import json
import os
import re
import time
import urllib.parse
import urllib.request

import boto3

INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
TERMINAL = {"Success", "Failed", "TimedOut", "Cancelled"}

_ssm = None


def ssm_client():
    global _ssm
    if _ssm is None:
        _ssm = boto3.client("ssm")
    return _ssm


def verify_telemetry(query):
    """Run a PromQL instant query. The query should return series only while the
    alert condition is violated (for example: disk_used_percent > 90)."""
    base = os.environ.get("PROMETHEUS_URL", "").rstrip("/")
    if not base:
        return {"status": "unavailable", "note": "PROMETHEUS_URL is not configured"}
    if not query:
        return {"status": "error", "error": "query is required"}
    url = f"{base}/api/v1/query?" + urllib.parse.urlencode({"query": query})
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return {"status": "unavailable", "error": str(exc)}
    if data.get("status") != "success":
        return {"status": "error", "error": data.get("error", "query failed")}
    series = data.get("data", {}).get("result", [])
    if not series:
        return {"status": "clear", "series": 0}
    first = series[0].get("value", [None, None])[1]
    return {"status": "active", "series": len(series), "value": first}


def execute_remediation(runbook_name, target_id):
    if not runbook_name or not runbook_name.startswith("AIOps-"):
        return {"status": "Rejected", "reason": "Runbook name must start with AIOps-."}
    if not target_id or not INSTANCE_ID_RE.match(target_id):
        return {"status": "Rejected", "reason": "target_id must be an EC2 instance id."}
    params = {"InstanceId": [target_id]}
    role = os.environ.get("AUTOMATION_ASSUME_ROLE")
    if role:
        params["AutomationAssumeRole"] = [role]
    try:
        started = ssm_client().start_automation_execution(DocumentName=runbook_name, Parameters=params)
    except Exception as exc:
        return {"status": "Failed", "error": str(exc)}

    execution_id = started["AutomationExecutionId"]
    deadline = time.time() + int(os.environ.get("WAIT_SECONDS", "40"))
    final = "InProgress"
    while time.time() < deadline:
        try:
            info = ssm_client().get_automation_execution(AutomationExecutionId=execution_id)
            final = info["AutomationExecution"]["AutomationExecutionStatus"]
        except Exception as exc:
            return {"status": "Failed", "execution_id": execution_id, "error": str(exc)}
        if final in TERMINAL:
            break
        time.sleep(3)

    if final == "Success":
        status = "Success"
    elif final in TERMINAL:
        status = "Failed"
    else:
        status = "InProgress"
    return {"status": status, "execution_id": execution_id, "automation_status": final}


def handler(event, context):
    action_group = event.get("actionGroup")
    function = event.get("function")
    parameters = {p["name"]: p["value"] for p in event.get("parameters", [])}

    if function == "QueryTelemetry":
        result = verify_telemetry(parameters.get("query"))
    elif function == "ExecuteRemediation":
        result = execute_remediation(parameters.get("runbook_name"), parameters.get("target_id"))
    else:
        result = {"error": "Function missing or unrecognized."}

    return {
        "response": {
            "actionGroup": action_group,
            "function": function,
            "functionResponse": {"responseBody": {"TEXT": json.dumps(result)}},
        }
    }
