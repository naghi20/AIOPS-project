# AI-Driven AIOps Orchestration Pipeline

Production-grade automated incident response structure powered by Amazon Bedrock agents, OpenSearch Serverless, and AWS Systems Manager.

## 🚀 Deployment Sequence
1. Deploy `infrastructure/phase1-base.yaml` (Creates SQS, S3 knowledge bases, secrets).
2. Deploy `infrastructure/phase2-ingress.yaml` (Builds HTTP webhook api and ingestion lambdas).
3. Deploy `infrastructure/phase3-vector-store.yaml` (Sets up OpenSearch vector collection and Bedrock Knowledge Base schemas).
4. Package and point tool code towards `infrastructure/phase5-agent.yaml` to spin up the core generative orchestrator.
