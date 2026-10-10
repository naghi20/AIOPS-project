import os
import json
import boto3

ssm = boto3.client('ssm')

def verify_telemetry(metric_query):
    print(f"Querying telemetry endpoint metric: {metric_query}")
    return {"status": "active", "value": 92.5}

def execute_remediation(runbook_name, target_id):
    if not runbook_name.startswith("AIOps-"):
        return {"status": "Rejected", "reason": "Fails prefix criteria rules definition."}
    try:
        response = ssm.start_automation_execution(
            DocumentName=runbook_name,
            Parameters={'InstanceId': [target_id]}
        )
        return {"status": "Success", "execution_id": response['AutomationExecutionId']}
    except Exception as e:
        return {"status": "Failed", "error": str(e)}

def handler(event, context):
    actionGroup = event.get('actionGroup')
    function = event.get('function')
    parameters = {p['name']: p['value'] for p in event.get('parameters', [])}
    
    if function == 'QueryTelemetry':
        result = verify_telemetry(parameters.get('query'))
    elif function == 'ExecuteRemediation':
        result = execute_remediation(parameters.get('runbook_name'), parameters.get('target_id'))
    else:
        result = {"error": "Function missing or unrecognized."}

    return {
        'response': {
            'actionGroup': actionGroup,
            'function': function,
            'functionResponse': {
                'responseBody': {'TEXT': json.dumps(result)}
            }
        }
    }
