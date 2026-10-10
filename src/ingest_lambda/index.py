import os
import json
import boto3
import urllib.request
import urllib.parse
import base64

bedrock_agent_runtime = boto3.client('bedrock-agent-runtime')
secrets_manager = boto3.client('secretsmanager')

def get_servicenow_credentials():
    secret_arn = os.environ['SERVICENOW_SECRET_ARN']
    response = secrets_manager.get_secret_value(SecretId=secret_arn)
    return json.loads(response['SecretString'])

def create_servicenow_incident(creds, alert_payload):
    instance_url = creds.get('instance_url').rstrip('/')
    api_url = f"{instance_url}/api/now/table/incident"
    
    alert_name = alert_payload.get('alertname', 'Unknown AIOps Alert')
    severity = alert_payload.get('severity', 'critical')

    incident_data = {
        "short_description": f"[AIOps Alert] {alert_name}",
        "description": f"Automated AIOps Ingestion Triggered.\nPayload:\n{json.dumps(alert_payload, indent=2)}",
        "urgency": "1" if severity == "critical" else "2",
        "impact": "2",
        "comments": "System assigned to Bedrock AI Orchestrator Agent for auto-remediation."
    }
    
    data_bytes = json.dumps(incident_data).encode('utf-8')
    req = urllib.request.Request(api_url, data=data_bytes, method='POST')
    
    auth_str = f"{creds.get('user')}:{creds.get('password')}"
    auth_encoded = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
    
    req.add_header('Authorization', f'Basic {auth_encoded}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_body = json.loads(response.read().decode('utf-8'))
            result = res_body.get('result', {})
            return result.get('number', 'UNKNOWN'), result.get('sys_id')
    except Exception as e:
        print(f"[-] ServiceNow integration connection issue: {str(e)}")
        return "FALLBACK_NUM", None

def invoke_bedrock_agent(alert_payload, session_id):
    prompt_text = f"Process this alert snapshot payload immediately and execute resolution plans: {json.dumps(alert_payload)}"
    response = bedrock_agent_runtime.invoke_agent(
        agentId=os.environ['BEDROCK_AGENT_ID'],
        agentAliasId=os.environ['BEDROCK_AGENT_ALIAS_ID'],
        sessionId=session_id,
        inputText=prompt_text
    )
    completion = ""
    for event in response.get('completion', []):
        chunk = event.get('chunk', {})
        if chunk:
            completion += chunk.get('bytes', b'').decode('utf-8')
    return completion

def handler(event, context):
    for record in event.get('Records', []):
        message_id = record.get('messageId')
        try:
            alert_payload = json.loads(record.get('body', '{}'))
        except Exception:
            alert_payload = {"raw_payload": record.get('body', '')}
            
        try:
            creds = get_servicenow_credentials()
            ticket_num, sys_id = create_servicenow_incident(creds, alert_payload)
            alert_payload['servicenow_ticket'] = ticket_num
            alert_payload['servicenow_sys_id'] = sys_id
        except Exception as e:
            print(f"Skipping ServiceNow block due to: {str(e)}")

        try:
            summary = invoke_bedrock_agent(alert_payload, session_id=message_id)
            print(f"[+] Execution completed summary: {summary}")
        except Exception as e:
            print(f"[-] Agent routing failure: {str(e)}")
            
    return {'statusCode': 200, 'body': 'Ingestion pipeline execution loop finished.'}
