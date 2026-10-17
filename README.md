<img width="3200" height="2000" alt="AIOps_AWS_Architecture" src="https://github.com/user-attachments/assets/ded0a566-18ae-4001-9eeb-846dca447748" />

Production-grade automated incident response structure powered by Amazon Bedrock agents, OpenSearch Serverless, and AWS Systems Manager.

# AI-Driven AIOps Orchestration Pipeline

Automated incident-response pipeline on AWS. An alert arrives at a webhook, is ingested and queued, matched against operational runbooks stored in a vector knowledge base, and handed to a generative-AI orchestrator that decides which remediation tool to run (for example an AWS Systems Manager automation).

Everything is defined as infrastructure-as-code (CloudFormation) and deployed by GitHub Actions using short-lived OIDC credentials. No long-term AWS keys are stored in GitHub.

> **Project status:** Phases 1 to 4 are deployed. Phase 5 (the AI orchestrator) is being redesigned. See [Phase 5 status](#phase-5-orchestrator-status) for why.

---

## Table of contents

1. [Architecture](#architecture)
2. [Repository layout](#repository-layout)
3. [Deployment phases](#deployment-phases)
4. [Prerequisites](#prerequisites)
5. [One-time AWS setup (OIDC and deploy role)](#one-time-aws-setup-oidc-and-deploy-role)
6. [GitHub configuration](#github-configuration)
7. [Deploying](#deploying)
8. [Verifying each phase](#verifying-each-phase)
9. [Loading runbooks into the knowledge base](#loading-runbooks-into-the-knowledge-base)
10. [Phase 5 orchestrator status](#phase-5-orchestrator-status)
11. [Troubleshooting](#troubleshooting)
12. [Security notes](#security-notes)
13. [Cost and teardown](#cost-and-teardown)
14. [Roadmap](#roadmap)

---

## Architecture

```
   Monitoring tool / alert
            |
            v   HTTPS POST
   +---------------------+
   |  API Gateway (HTTP) |   Phase 2
   +---------------------+
            |
            v
   +---------------------+        +-------------------+
   |  Ingestion Lambda   | -----> |   SQS alert queue |   Phase 1 / 2
   +---------------------+        +-------------------+
                                           |
                                           v
                              +---------------------------+
                              |  Orchestrator  (Phase 5)  |
                              |  Claude on Amazon Bedrock |
                              +---------------------------+
                                  |                  |
                  runbook lookup  |                  |  tool calls
                                  v                  v
              +------------------------------+   +--------------------+
              | Bedrock Knowledge Base       |   | Tool Lambda        |  Phase 4
              | (OpenSearch Serverless       |   | - QueryTelemetry   |
              |  vector index + S3 runbooks) |   | - ExecuteRemediation
              |        Phase 3 / 3b          |   |   (SSM automation) |
              +------------------------------+   +--------------------+
```

The flow shown reflects the intended design. The orchestrator box is the part still being rebuilt (see Phase 5 status).

| Component | AWS service | Purpose |
|---|---|---|
| Webhook | API Gateway (HTTP API) | Receives alerts |
| Ingestion | Lambda | Accepts and queues alerts |
| Queue | SQS | Buffers alerts |
| Runbook storage | S3 | Runbook documents and Lambda code packages |
| Vector store | OpenSearch Serverless (VECTORSEARCH) | Semantic search over runbooks |
| Knowledge base | Amazon Bedrock Knowledge Bases | Retrieval over the vector store |
| Tools | Lambda | Telemetry checks and remediation actions |
| Remediation | AWS Systems Manager | Executes approved automations |
| Orchestrator | Amazon Bedrock (Claude) | Reasoning and tool selection |
| Deployment | GitHub Actions + CloudFormation + OIDC | CI/CD |

---

## Repository layout

```
.
|-- .github/workflows/deploy.yml     # CI/CD pipeline (all phases)
|-- infrastructure/
|   |-- phase1-base.yaml             # SQS, S3, secrets, budget alert
|   |-- phase2-ingress.yaml          # HTTP API + ingestion Lambda
|   |-- phase3-vector-store.yaml     # OpenSearch collection, policies, KB role
|   |-- phase3b-knowledge-base.yaml  # Bedrock Knowledge Base + S3 data source
|   |-- phase4-tools.yaml            # Tool Lambda used by the orchestrator
|   `-- phase5-*.yaml                # Orchestrator (being redesigned)
|-- src/
|   |-- ingest_lambda/index.py       # Ingestion Lambda (handler: index.handler)
|   `-- tool_lambda/index.py         # Tool Lambda   (handler: index.handler)
|-- automation/                      # Automation / runbook helper content
|-- tests/                           # Tests
`-- README.md
```

Lambda packages must have `index.py` at the **root of the zip**. The pipeline builds each zip from inside its own folder to guarantee this.

---

## Deployment phases

Each phase is its own CloudFormation stack. Order matters because later stacks use outputs of earlier ones.

| Phase | Stack name | Template | Creates |
|---|---|---|---|
| 1 | `aiops-phase1-base` | `phase1-base.yaml` | SQS queue, S3 runbooks bucket, secrets, budget alert |
| (pkg) | n/a | workflow step | Zips Lambda code and uploads to `s3://aiops-runbooks-<ACCOUNT_ID>-us-east-1/src/` |
| 2 | `aiops-phase2-ingress` | `phase2-ingress.yaml` | HTTP API webhook, ingestion Lambda, its IAM role |
| 3 | `aiops-phase3-vector-store` | `phase3-vector-store.yaml` | OpenSearch Serverless collection, encryption/network/data-access policies, Knowledge Base service role |
| (index) | n/a | workflow step | Creates the vector index `aiops-index` inside the collection |
| 3b | `aiops-phase3b-knowledge-base` | `phase3b-knowledge-base.yaml` | Bedrock Knowledge Base and S3 data source |
| 4 | `aiops-phase4-tools` | `phase4-tools.yaml` | Tool Lambda, its role, Bedrock invoke permission |
| 5 | n/a yet | n/a | Orchestrator (redesign in progress) |

### Why the index step exists

CloudFormation can create an OpenSearch Serverless collection but not an index inside it, and a Bedrock Knowledge Base fails to create if its index does not exist. The pipeline therefore deploys the collection (Phase 3), creates the index with a signed request, then deploys the Knowledge Base (Phase 3b).

The index uses a `knn_vector` field named `vector` with **1024 dimensions** (the default for Amazon Titan Text Embeddings V2), plus `text` and `metadata` fields. If you change the embedding model, change the dimension to match.

---

## Prerequisites

- An AWS account and the AWS CLI (CloudShell works).
- Amazon Bedrock access in `us-east-1` for the embedding model (`amazon.titan-embed-text-v2:0`) and the Claude model you choose for the orchestrator. Anthropic models may require a one-time use-case form.
- A GitHub repository with Actions enabled.
- Region used throughout: `us-east-1`.

---

## One-time AWS setup (OIDC and deploy role)

GitHub Actions authenticates to AWS with OpenID Connect. Do this once per AWS account.

### 1. Create the identity provider

IAM > Identity providers > Add provider > OpenID Connect

| Field | Value |
|---|---|
| Provider URL | `https://token.actions.githubusercontent.com` |
| Audience | `sts.amazonaws.com` |

### 2. Create the deploy role

Create a role named `github-actions-AIOPS-project-deploy-role` and set its **trust policy** to:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:<OWNER>@<OWNER_ID>/<REPO>@<REPO_ID>:*"
      }
    }
  }]
}
```

> **Important: the subject claim format.** Depending on repository settings, GitHub puts the numeric owner and repository IDs in the token subject, for example
> `repo:naghi20@64667680/AIOPS-project@1412340039:ref:refs/heads/main`.
> A plain `repo:owner/repo:*` pattern then never matches and the role assumption fails with `Not authorized to perform sts:AssumeRoleWithWebIdentity`.
> To see your real value, open the failed `AssumeRoleWithWebIdentity` event in CloudTrail and copy `userName`, or check the claim in your workflow's OIDC token.
> Once everything works, tighten `:*` to `:ref:refs/heads/main` so only `main` can deploy.

### 3. Permissions

For building, the role has broad permissions. For anything beyond a learning project, replace this with a least-privilege policy limited to: CloudFormation, S3, SQS, Secrets Manager, Lambda, API Gateway, CloudWatch Logs, EventBridge, SNS, Budgets, SSM, OpenSearch Serverless (`aoss`), Bedrock, and the IAM role actions CloudFormation needs (`CreateRole`, `PassRole`, `PutRolePolicy`, `AttachRolePolicy` and their delete counterparts).

---

## GitHub configuration

Repository > Settings > Secrets and variables > Actions > **New repository secret**

| Secret | Value |
|---|---|
| `AWS_ROLE_TO_ASSUME` | Full ARN of the deploy role, `arn:aws:iam::<ACCOUNT_ID>:role/github-actions-AIOPS-project-deploy-role` |
| `BUDGET_EMAIL` | Email address that receives the budget alert (Phase 1 parameter) |

The workflow needs these permissions at the top level:

```yaml
permissions:
  id-token: write   # required for OIDC
  contents: read
```

---

## Deploying

The workflow runs on every push to `main` and can also be started manually (Actions > the workflow > **Run workflow**).

```
Checkout
  -> Configure AWS credentials (OIDC)
  -> Deploy Phase 1
  -> Package and upload Lambda code to S3
  -> Deploy Phase 2
  -> Deploy Phase 3 (collection)
  -> Create vector index
  -> Deploy Phase 3b (knowledge base)
  -> Deploy Phase 4 (tool Lambda)
```

Rules that avoid the most common failures:

1. **Start a new run after editing the workflow.** "Re-run jobs" replays the *original commit's* workflow file and ignores your fixes. Push a new commit or use Run workflow.
2. **Every stack that creates IAM roles needs** `capabilities: CAPABILITY_IAM,CAPABILITY_NAMED_IAM`.
3. **Keep one shell command per line** inside `run: |` blocks, and use subshells such as `(cd dir && zip ...)` so the working directory never changes.
4. **Delete failed first-time stacks.** A stack left in `ROLLBACK_COMPLETE` cannot be updated and must be deleted before the next deploy.

Packaging step, for reference:

```yaml
- name: Package and upload Lambda code
  run: |
    BUCKET="aiops-runbooks-<ACCOUNT_ID>-us-east-1"
    (cd src/ingest_lambda && zip -r ../../ingest_lambda.zip . -x "*.pyc" "__pycache__/*")
    (cd src/tool_lambda && zip -r ../../tool_lambda.zip . -x "*.pyc" "__pycache__/*")
    unzip -l ingest_lambda.zip
    aws s3 cp ingest_lambda.zip "s3://${BUCKET}/src/ingest_lambda.zip"
    aws s3 cp tool_lambda.zip "s3://${BUCKET}/src/tool_lambda.zip"
```

---

## Verifying each phase

| Phase | Check |
|---|---|
| 1 | Stack `CREATE_COMPLETE`; bucket `aiops-runbooks-<ACCOUNT_ID>-us-east-1` exists |
| Packaging | `aws s3 ls s3://aiops-runbooks-<ACCOUNT_ID>-us-east-1/src/` lists both zips |
| 2 | Stack `CREATE_COMPLETE`; take the API endpoint from the stack outputs and send a test POST (below) |
| 3 | OpenSearch Serverless collection is `ACTIVE` |
| Index | The index step prints a mapping containing `knn_vector` |
| 3b | Knowledge Base visible in Bedrock; the data source can be synced |
| 4 | Tool Lambda exists; `ToolLambdaArn` appears in the stack outputs |

Test the webhook (replace the URL with your stack output; the payload shape depends on your ingestion Lambda):

```bash
curl -X POST "https://<api-id>.execute-api.us-east-1.amazonaws.com/<route>" \
  -H "Content-Type: application/json" \
  -d '{"alert":"HighCPU","instance":"i-0123456789abcdef0","severity":"critical"}'
```

Then check the ingestion Lambda's log group in CloudWatch Logs.

---

## Loading runbooks into the knowledge base

1. Upload runbook documents (Markdown, text or PDF) to the runbooks bucket, for example under a `runbooks/` prefix:
   ```bash
   aws s3 cp ./runbooks/ s3://aiops-runbooks-<ACCOUNT_ID>-us-east-1/runbooks/ --recursive
   ```
2. Bedrock console > Knowledge bases > your knowledge base > Data source > **Sync**.
3. Test retrieval in the console's test panel before wiring it to the orchestrator.

Runbooks that name the remediation script (the `AIOps-` prefix convention) let the orchestrator pick the right action.

---

## Phase 5 orchestrator status

The original design used an **Amazon Bedrock Agent** (`AWS::Bedrock::Agent`). That cannot be deployed in this account.

AWS placed Bedrock Agents (Classic) in maintenance mode on **30 July 2026**: new agents cannot be created in accounts without Bedrock Agents activity in the previous 12 months, and AWS states there is no exception process. CloudFormation's `AWS::Bedrock::Agent` calls the same `CreateAgent` API and fails with `AccessDenied`. Knowledge Bases, models and Guardrails are not affected, so Phases 1 to 4 remain valid.
Reference: [Bedrock Agents Classic maintenance mode](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-classic-maintenance-mode.html).

Options being considered for the replacement:

| Option | Description |
|---|---|
| **A. Orchestrator Lambda** | A Lambda that calls Claude through the Bedrock Converse API with tool definitions, retrieves runbooks from the Knowledge Base and invokes the tool Lambda. Plain CloudFormation, minimal cost. |
| **B. Bedrock AgentCore** | AWS's recommended replacement: a managed harness or code-defined agents, with the Knowledge Base connected through its gateway. |

The planned orchestrator instructions are unchanged: parse the alert, look up matching runbooks, verify the anomaly with `QueryTelemetry`, pick a remediation named with the `AIOps-` prefix, run it with `ExecuteRemediation`, and log the outcome.

---

## Troubleshooting

Where to look, in this order:

1. **GitHub Actions log.** Expand the first "Run ..." group to confirm the inputs actually used.
2. **CloudFormation > Stack > Events.** Find the first `CREATE_FAILED` row. For a rolled-back stack, use the **Deleted** filter.
3. **CloudTrail > Event history.** Filter by user name `GitHubActions`; `errorCode` and `errorMessage` name the failed API call.
4. **CloudWatch Logs** for runtime errors inside the Lambdas.

| Error | Meaning and fix |
|---|---|
| `Not authorized to perform sts:AssumeRoleWithWebIdentity` | Trust policy `sub` or `aud` does not match the token. Use the real subject format with IDs. |
| No OIDC token / credentials not loaded | Missing `permissions: id-token: write` in the workflow. |
| `Requires capabilities : [CAPABILITY_NAMED_IAM]` | Add `capabilities: CAPABILITY_IAM,CAPABILITY_NAMED_IAM` to that step. |
| Same error after fixing the file | You used "Re-run jobs". Start a new run. |
| `S3 Error Code: NoSuchKey` | A Lambda zip was not uploaded, or the `S3Key` in the template differs from the upload path. |
| `... does not exist` in the packaging step | Commands merged onto one line or a wrong `cd`. Use one command per line and subshells. |
| `Runtime.ImportModuleError: No module named 'index'` | `index.py` is not at the zip root. |
| `Stack ... is in ROLLBACK_COMPLETE state and can not be updated` | Delete the stack, fix the cause, redeploy. |
| `Unsupported property` on the Knowledge Base | Property names are case-sensitive: `OpensearchServerlessConfiguration`, and `VectorField` / `TextField` / `MetadataField` in `FieldMapping`. |
| Network policy rejected | OpenSearch Serverless network policies must be a JSON **array**. |
| Knowledge Base fails to create (index) | The vector index does not exist yet; the index step must run first. |
| `Parameters: [X] do not exist in the template` | Workflow passes a parameter the committed template does not declare. Commit both together. |
| `Parameters: [X] must have values` | Parameter has no default and is not passed in `parameter-overrides`. |
| `Access denied for operation 'AWS::Bedrock::Agent'` | Bedrock Agents Classic is closed to new accounts. See Phase 5 status. |
| 403 from the OpenSearch index request | Deploy role not in the data-access policy, or the policy has not propagated yet (wait about a minute). |

---

## Security notes

- OIDC means there are no stored AWS access keys. Never commit keys or secrets.
- Narrow the trust policy to `main` once things work, and run deployments only on push to `main` or manual dispatch, not on pull requests.
- Replace broad deploy-role permissions with least privilege.
- The webhook is public. Protect it with an API key, a shared-secret header or request validation in the ingestion Lambda.
- The remediation tool should only run automations whose names start with `AIOps-`, validate target identifiers, and log every action.
- Keep the budget alert active.

---

## Cost and teardown

OpenSearch Serverless is billed while the collection exists, even when idle. When you are not working on the project, delete the stacks in reverse order:

```bash
aws cloudformation delete-stack --stack-name aiops-phase4-tools
aws cloudformation delete-stack --stack-name aiops-phase3b-knowledge-base
aws cloudformation delete-stack --stack-name aiops-phase3-vector-store
aws cloudformation delete-stack --stack-name aiops-phase2-ingress
# empty the S3 bucket first, then:
aws cloudformation delete-stack --stack-name aiops-phase1-base
```

The next push to `main` recreates everything.

---

## Roadmap

- [x] OIDC authentication from GitHub Actions
- [x] Phase 1: base infrastructure
- [x] Lambda packaging and upload
- [x] Phase 2: webhook and ingestion
- [x] Phase 3 / 3b: vector store and knowledge base
- [x] Phase 4: tool Lambda
- [ ] Phase 5: orchestrator (redesign: Lambda or AgentCore)
- [ ] Connect ingestion queue to the orchestrator
- [ ] Load runbooks and sync the knowledge base
- [ ] Implement and test `QueryTelemetry` and `ExecuteRemediation`
- [ ] End-to-end alert test
- [ ] Automated tests in the workflow
- [ ] Least-privilege IAM and webhook authentication
