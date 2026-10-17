"""Webhook receiver (API Gateway -> this Lambda -> SQS).

Checks the shared-secret header, splits a Grafana webhook into one message per
firing alert, and puts each message on the alert queue. It does no other work,
so it answers the monitoring tool quickly.
"""
import base64
import hashlib
import hmac
import json
import os
import re

import boto3

INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
INSTANCE_LABEL_KEYS = ("InstanceId", "instance_id", "instanceId", "instance")

_clients = {}
_token_cache = {"value": None}


def client(name):
    if name not in _clients:
        _clients[name] = boto3.client(name)
    return _clients[name]


def get_expected_token():
    if _token_cache["value"] is None:
        resp = client("secretsmanager").get_secret_value(SecretId=os.environ["SECRET_ID"])
        _token_cache["value"] = resp["SecretString"].strip()
    return _token_cache["value"]


def _instance_id(labels, alert):
    candidates = [labels.get(k) for k in INSTANCE_LABEL_KEYS] + [alert.get("instance_id")]
    for value in candidates:
        if isinstance(value, str) and INSTANCE_ID_RE.match(value):
            return value
    return None


def normalize_alerts(payload):
    """Return a list of flat alert dicts from a Grafana payload (or a flat test payload)."""
    alerts = payload.get("alerts")
    if not isinstance(alerts, list) or not alerts:
        alerts = [payload]
    out = []
    for a in alerts:
        if not isinstance(a, dict):
            continue
        labels = a.get("labels") or {}
        annotations = a.get("annotations") or {}
        alertname = labels.get("alertname") or a.get("alertname") or "UnknownAlert"
        instance_id = _instance_id(labels, a)
        fingerprint = a.get("fingerprint") or hashlib.sha1(
            f"{alertname}|{instance_id}".encode("utf-8")
        ).hexdigest()[:16]
        out.append(
            {
                "alertname": alertname,
                "severity": str(labels.get("severity") or a.get("severity") or "critical").lower(),
                "instance_id": instance_id,
                "summary": annotations.get("summary") or annotations.get("description") or a.get("summary") or "",
                "status": a.get("status") or payload.get("status") or "firing",
                "fingerprint": fingerprint,
                "labels": labels,
                "annotations": annotations,
            }
        )
    return out


def _response(status, body):
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body),
    }


def handler(event, context):
    headers = {str(k).lower(): v for k, v in (event.get("headers") or {}).items()}
    supplied = headers.get("x-aiops-token", "")
    try:
        expected = get_expected_token()
    except Exception as exc:  # secret missing or access denied
        print(f"[-] Could not load webhook token: {exc}")
        return _response(500, {"error": "server configuration error"})

    if not supplied or not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
        return _response(401, {"error": "unauthorized"})

    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return _response(400, {"error": "body must be JSON"})
    if not isinstance(payload, dict):
        return _response(400, {"error": "body must be a JSON object"})

    queued = 0
    skipped = 0
    for alert in normalize_alerts(payload):
        if str(alert["status"]).lower() != "firing":
            skipped += 1
            continue
        client("sqs").send_message(QueueUrl=os.environ["QUEUE_URL"], MessageBody=json.dumps(alert))
        queued += 1

    print(f"[+] queued={queued} skipped={skipped}")
    return _response(202, {"queued": queued, "skipped": skipped})
