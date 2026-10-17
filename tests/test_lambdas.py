"""Unit tests for the three Lambdas. No AWS access needed: clients are faked."""
import importlib.util
import io
import json
import os
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

GRAFANA_ALERT = {
    "status": "firing",
    "alerts": [
        {
            "labels": {"alertname": "HighDiskSpaceUtilization", "severity": "critical", "InstanceId": "i-0abcd1234ef56789a"},
            "annotations": {"summary": "Disk utilization exceeded 92% on target workloads."},
        }
    ],
}


def load(name):
    path = ROOT / "src" / name / "index.py"
    spec = importlib.util.spec_from_file_location(f"{name}_index", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ------------------------------------------------------------------ receiver
class FakeSqs:
    def __init__(self):
        self.sent = []

    def send_message(self, QueueUrl, MessageBody):
        self.sent.append(json.loads(MessageBody))


class FakeSecrets:
    def get_secret_value(self, SecretId):
        return {"SecretString": "s3cret-token"}


@pytest.fixture
def receiver(monkeypatch):
    mod = load("receiver_lambda")
    sqs = FakeSqs()
    monkeypatch.setenv("QUEUE_URL", "https://sqs/queue")
    monkeypatch.setenv("SECRET_ID", "aiops/webhook-token")
    monkeypatch.setattr(mod, "client", lambda name: sqs if name == "sqs" else FakeSecrets())
    mod._token_cache["value"] = None
    mod.sqs = sqs
    return mod


def api_event(body, token="s3cret-token"):
    headers = {"X-AIOps-Token": token} if token is not None else {}
    return {"headers": headers, "body": json.dumps(body), "isBase64Encoded": False}


def test_receiver_rejects_missing_or_wrong_token(receiver):
    assert receiver.handler(api_event(GRAFANA_ALERT, token=None), None)["statusCode"] == 401
    assert receiver.handler(api_event(GRAFANA_ALERT, token="nope"), None)["statusCode"] == 401
    assert receiver.sqs.sent == []


def test_receiver_queues_grafana_alert(receiver):
    resp = receiver.handler(api_event(GRAFANA_ALERT), None)
    assert resp["statusCode"] == 202
    assert len(receiver.sqs.sent) == 1
    msg = receiver.sqs.sent[0]
    assert msg["alertname"] == "HighDiskSpaceUtilization"
    assert msg["instance_id"] == "i-0abcd1234ef56789a"
    assert msg["severity"] == "critical"


def test_receiver_skips_resolved_and_splits_multiple(receiver):
    payload = {
        "alerts": [
            {"status": "firing", "labels": {"alertname": "A", "InstanceId": "i-0123456789abcdef0"}},
            {"status": "resolved", "labels": {"alertname": "B"}},
            {"status": "firing", "labels": {"alertname": "C", "instance": "10.0.0.5:9100"}},
        ]
    }
    resp = json.loads(receiver.handler(api_event(payload), None)["body"])
    assert resp == {"queued": 2, "skipped": 1}
    # a non-instance-id "instance" label is not trusted as an instance id
    assert receiver.sqs.sent[1]["instance_id"] is None


def test_receiver_bad_json(receiver):
    event = {"headers": {"x-aiops-token": "s3cret-token"}, "body": "{not json"}
    assert receiver.handler(event, None)["statusCode"] == 400


# ----------------------------------------------------------------- tool lambda
class FakeSsm:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.started = None

    def start_automation_execution(self, DocumentName, Parameters):
        self.started = (DocumentName, Parameters)
        return {"AutomationExecutionId": "exec-1"}

    def get_automation_execution(self, AutomationExecutionId):
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return {"AutomationExecution": {"AutomationExecutionStatus": status}}


def tool_event(function, **params):
    return {
        "actionGroup": "OperationalTools",
        "function": function,
        "parameters": [{"name": k, "type": "string", "value": v} for k, v in params.items()],
    }


def tool_result(response):
    return json.loads(response["response"]["functionResponse"]["responseBody"]["TEXT"])


@pytest.fixture
def tool(monkeypatch):
    mod = load("tool_lambda")
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    monkeypatch.setenv("AUTOMATION_ASSUME_ROLE", "arn:aws:iam::1:role/auto")
    return mod


def test_tool_rejects_bad_runbook_and_target(tool):
    r = tool_result(tool.handler(tool_event("ExecuteRemediation", runbook_name="Other-Thing", target_id="i-0123456789abcdef0"), None))
    assert r["status"] == "Rejected"
    r = tool_result(tool.handler(tool_event("ExecuteRemediation", runbook_name="AIOps-DiskCleanupWorkflow", target_id="not-an-id"), None))
    assert r["status"] == "Rejected"


def test_tool_runs_and_waits_for_success(tool, monkeypatch):
    fake = FakeSsm(["InProgress", "Success"])
    monkeypatch.setattr(tool, "ssm_client", lambda: fake)
    r = tool_result(tool.handler(tool_event("ExecuteRemediation", runbook_name="AIOps-DiskCleanupWorkflow", target_id="i-0123456789abcdef0"), None))
    assert r["status"] == "Success" and r["execution_id"] == "exec-1"
    assert fake.started[1]["AutomationAssumeRole"] == ["arn:aws:iam::1:role/auto"]


def test_tool_reports_failed_automation(tool, monkeypatch):
    monkeypatch.setattr(tool, "ssm_client", lambda: FakeSsm(["Failed"]))
    r = tool_result(tool.handler(tool_event("ExecuteRemediation", runbook_name="AIOps-DiskCleanupWorkflow", target_id="i-0123456789abcdef0"), None))
    assert r["status"] == "Failed"


def test_tool_telemetry_unavailable_without_url(tool, monkeypatch):
    monkeypatch.delenv("PROMETHEUS_URL", raising=False)
    r = tool_result(tool.handler(tool_event("QueryTelemetry", query="up"), None))
    assert r["status"] == "unavailable"


def test_tool_unknown_function(tool):
    assert "error" in tool_result(tool.handler(tool_event("Nope"), None))


# -------------------------------------------------------------------- processor
@pytest.fixture
def proc(monkeypatch):
    mod = load("processor_lambda")
    monkeypatch.setattr(mod, "MODEL_ID", "test-model")
    monkeypatch.setattr(mod, "TOOL_LAMBDA_ARN", "arn:tool")
    monkeypatch.setattr(mod, "KNOWLEDGE_BASE_ID", "KB1")
    monkeypatch.delenv("REMEDIATION_POLICY", raising=False)
    return mod


ALERT = {
    "alertname": "HighDiskSpaceUtilization",
    "severity": "critical",
    "instance_id": "i-0abcd1234ef56789a",
    "summary": "Disk > 92%",
    "status": "firing",
}


def test_normalize_handles_raw_grafana_and_flat(proc):
    a = proc.normalize_alert(GRAFANA_ALERT)
    assert a["alertname"] == "HighDiskSpaceUtilization" and a["instance_id"] == "i-0abcd1234ef56789a"
    b = proc.normalize_alert(ALERT)
    assert b["alertname"] == "HighDiskSpaceUtilization" and b["instance_id"] == "i-0abcd1234ef56789a"


def test_policy_gate(proc):
    ok, _ = proc.policy_gate("AIOps-DiskCleanupWorkflow", "i-0abcd1234ef56789a", ALERT)
    assert ok
    assert not proc.policy_gate("AIOps-Unlisted", "i-0abcd1234ef56789a", ALERT)[0]
    assert not proc.policy_gate("DeleteEverything", "i-0abcd1234ef56789a", ALERT)[0]
    assert not proc.policy_gate("AIOps-DiskCleanupWorkflow", "i-0123456789abcdef0", ALERT)[0]  # not the alert's instance
    assert not proc.policy_gate("AIOps-DiskCleanupWorkflow", "i-0abcd1234ef56789a", {**ALERT, "instance_id": None})[0]


def test_policy_gate_blocks_medium_risk(proc, monkeypatch):
    monkeypatch.setenv("REMEDIATION_POLICY", json.dumps({"AIOps-RestartService": "medium"}))
    ok, reason = proc.policy_gate("AIOps-RestartService", "i-0abcd1234ef56789a", ALERT)
    assert not ok and "approval" in reason


def test_parse_result(proc):
    assert proc.parse_result("Done.\nRESULT: RESOLVED") == "RESOLVED"
    assert proc.parse_result("Hmm\nRESULT: ESCALATE") == "ESCALATE"
    assert proc.parse_result("no verdict line") == "ESCALATE"


class FakeBedrock:
    """Scripted Converse responses: tool call, tool call, final answer."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def converse(self, **kwargs):
        self.calls += 1
        return self.script.pop(0)


def tool_use(use_id, name, inp):
    return {"stopReason": "tool_use", "output": {"message": {"role": "assistant", "content": [{"toolUse": {"toolUseId": use_id, "name": name, "input": inp}}]}}}


def final(text):
    return {"stopReason": "end_turn", "output": {"message": {"role": "assistant", "content": [{"text": text}]}}}


class FakeLambda:
    def __init__(self):
        self.events = []

    def invoke(self, FunctionName, Payload):
        event = json.loads(Payload)
        self.events.append(event)
        if event["function"] == "QueryTelemetry":
            body = {"status": "active", "value": "92.5"}
        else:
            body = {"status": "Success", "execution_id": "exec-1"}
        out = {"response": {"functionResponse": {"responseBody": {"TEXT": json.dumps(body)}}}}
        return {"Payload": io.BytesIO(json.dumps(out).encode())}


def test_orchestrate_happy_path(proc, monkeypatch):
    bedrock = FakeBedrock([
        tool_use("1", "QueryTelemetry", {"query": "disk > 90"}),
        tool_use("2", "ExecuteRemediation", {"runbook_name": "AIOps-DiskCleanupWorkflow", "target_id": "i-0abcd1234ef56789a"}),
        final("Cleaned the disk.\nRESULT: RESOLVED"),
    ])
    lam = FakeLambda()
    monkeypatch.setattr(proc, "client", lambda name: bedrock if name == "bedrock-runtime" else lam)
    text, log = proc.orchestrate(ALERT, ["Run AIOps-DiskCleanupWorkflow for disk alerts"])
    assert proc.parse_result(text) == "RESOLVED"
    assert [e["function"] for e in lam.events] == ["QueryTelemetry", "ExecuteRemediation"]
    assert lam.events[1]["parameters"][1] == {"name": "target_id", "type": "string", "value": "i-0abcd1234ef56789a"}
    assert any("policy gate" in line for line in log)


def test_orchestrate_blocks_disallowed_remediation(proc, monkeypatch):
    bedrock = FakeBedrock([
        tool_use("1", "ExecuteRemediation", {"runbook_name": "AIOps-Evil", "target_id": "i-0abcd1234ef56789a"}),
        final("Not allowed.\nRESULT: ESCALATE"),
    ])
    lam = FakeLambda()
    monkeypatch.setattr(proc, "client", lambda name: bedrock if name == "bedrock-runtime" else lam)
    text, log = proc.orchestrate(ALERT, [])
    assert lam.events == []  # the tool Lambda was never called
    assert proc.parse_result(text) == "ESCALATE"


def test_orchestrate_turn_limit(proc, monkeypatch):
    monkeypatch.setattr(proc, "MAX_TURNS", 2)
    bedrock = FakeBedrock([tool_use(str(i), "QueryTelemetry", {"query": "x"}) for i in range(5)])
    monkeypatch.setattr(proc, "client", lambda name: bedrock if name == "bedrock-runtime" else FakeLambda())
    text, _ = proc.orchestrate(ALERT, [])
    assert proc.parse_result(text) == "ESCALATE" and bedrock.calls == 2


def test_handler_reports_failed_records_for_retry(proc, monkeypatch):
    def boom(record):
        raise RuntimeError("bedrock throttled")

    monkeypatch.setattr(proc, "process_record", boom)
    out = proc.handler({"Records": [{"messageId": "m1", "body": "{}"}]}, None)
    assert out == {"batchItemFailures": [{"itemIdentifier": "m1"}]}


def test_process_record_resolves_ticket(proc, monkeypatch):
    updates = []
    monkeypatch.setattr(proc, "get_servicenow_credentials", lambda: {"instance_url": "https://x", "user": "u", "password": "p"})
    monkeypatch.setattr(proc, "create_incident", lambda creds, alert: ("INC001", "sys1"))
    monkeypatch.setattr(proc, "update_incident", lambda creds, sys_id, fields: updates.append(fields))
    monkeypatch.setattr(proc, "retrieve_runbooks", lambda alert: ["runbook"])
    monkeypatch.setattr(proc, "orchestrate", lambda alert, rb: ("Fixed.\nRESULT: RESOLVED", ["step"]))
    proc.process_record({"messageId": "m1", "body": json.dumps(ALERT)})
    assert updates[0]["state"] == "2"
    assert updates[-1]["state"] == "6" and updates[-1]["close_code"]


def test_process_record_escalation_leaves_ticket_open(proc, monkeypatch):
    updates = []
    monkeypatch.setattr(proc, "get_servicenow_credentials", lambda: {"instance_url": "https://x", "user": "u", "password": "p"})
    monkeypatch.setattr(proc, "create_incident", lambda creds, alert: ("INC001", "sys1"))
    monkeypatch.setattr(proc, "update_incident", lambda creds, sys_id, fields: updates.append(fields))
    monkeypatch.setattr(proc, "retrieve_runbooks", lambda alert: [])
    monkeypatch.setattr(proc, "orchestrate", lambda alert, rb: ("No runbook.\nRESULT: ESCALATE", []))
    proc.process_record({"messageId": "m1", "body": json.dumps(ALERT)})
    assert "state" not in updates[-1] and "Escalated" in updates[-1]["work_notes"]


def test_process_record_without_servicenow_still_runs(proc, monkeypatch):
    monkeypatch.setattr(proc, "get_servicenow_credentials", lambda: None)
    monkeypatch.setattr(proc, "retrieve_runbooks", lambda alert: [])
    monkeypatch.setattr(proc, "orchestrate", lambda alert, rb: ("ok\nRESULT: RESOLVED", []))
    proc.process_record({"messageId": "m1", "body": json.dumps(ALERT)})  # must not raise


def test_resolved_alert_is_skipped(proc, monkeypatch):
    monkeypatch.setattr(proc, "orchestrate", lambda *a: pytest.fail("should not orchestrate"))
    proc.process_record({"messageId": "m1", "body": json.dumps({**ALERT, "status": "resolved"})})
