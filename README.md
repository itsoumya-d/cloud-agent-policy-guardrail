# cloud-agent-policy-guardrail

Deterministic security, cost, and compliance policy guardrail engine for AI-agent-directed cloud infrastructure actions and Terraform resource manifests.

## Overview
Autonomous engineering agents operating on AWS, Azure, and GCP require strict pre-execution guardrails before synthesizing or modifying Infrastructure as Code (IaC) or deploying runtime resources. This engine evaluates agent action plans and synthesized resource definitions against:
- **IAM Least Privilege**: Prevents wildcard permissions (`*`), cross-account assumption bypasses, and unconstrained admin bindings.
- **Mandatory Compliance Tagging**: Enforces required metadata tags (`Environment`, `Owner`, `CostCenter`, `DataClassification`) on cloud resources.
- **Egress & Ingress Boundary Control**: Detects and rejects open ingress/egress rules (`0.0.0.0/0`) on non-public subnets and security groups.
- **Cost Ceiling Evaluation**: Computes estimated monthly infrastructure expenditure against team budget limits and halts policy violations.

## Installation & Testing
```bash
pip install -r requirements.txt
pytest -v
```
