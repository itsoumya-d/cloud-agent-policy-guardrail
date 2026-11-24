from src.cloud_guardrail.models import ResourcePlan, Severity
from src.cloud_guardrail.evaluator import PolicyEvaluator


def test_compliant_plan():
    evaluator = PolicyEvaluator(monthly_budget_ceiling=500.0)
    plan = [
        ResourcePlan(
            resource_id="aws_instance.app_server",
            resource_type="aws_instance",
            tags={"Environment": "production", "Owner": "infra-team", "CostCenter": "CC-102"},
            properties={"instance_type": "t4g.small"},
            estimated_monthly_cost=25.0,
        )
    ]
    result = evaluator.evaluate_plan(plan)
    assert result.is_compliant is True
    assert len(result.violations) == 0
    assert result.total_estimated_monthly_cost == 25.0


def test_missing_tags_and_budget_exceeded():
    evaluator = PolicyEvaluator(monthly_budget_ceiling=100.0)
    plan = [
        ResourcePlan(
            resource_id="aws_instance.gpu_node",
            resource_type="aws_instance",
            tags={"Environment": "dev"},
            estimated_monthly_cost=150.0,
        )
    ]
    result = evaluator.evaluate_plan(plan)
    assert result.is_compliant is False
    rule_ids = [v.rule_id for v in result.violations]
    assert "TAG-001" in rule_ids
    assert "COST-001" in rule_ids


def test_iam_wildcard_rejection():
    evaluator = PolicyEvaluator()
    plan = [
        ResourcePlan(
            resource_id="aws_iam_policy.admin_role",
            resource_type="aws_iam_policy",
            tags={"Environment": "prod", "Owner": "security", "CostCenter": "CC-101"},
            properties={
                "policy_document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"}
                    ]
                }
            },
        )
    ]
    result = evaluator.evaluate_plan(plan)
    assert result.is_compliant is False
    assert any(v.rule_id == "IAM-001" and v.severity == Severity.CRITICAL for v in result.violations)


def test_security_group_open_ssh_rejection():
    evaluator = PolicyEvaluator()
    plan = [
        ResourcePlan(
            resource_id="aws_security_group.web",
            resource_type="aws_security_group",
            tags={"Environment": "staging", "Owner": "devops", "CostCenter": "CC-101"},
            properties={
                "ingress": [
                    {"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "to_port": 22, "protocol": "tcp"}
                ]
            },
        )
    ]
    result = evaluator.evaluate_plan(plan)
    assert result.is_compliant is False
    assert any(v.rule_id == "NET-001" and v.severity == Severity.HIGH for v in result.violations)
