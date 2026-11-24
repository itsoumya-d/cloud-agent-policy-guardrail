from typing import List, Set, Optional
from .models import ResourcePlan, PolicyViolation, EvaluationResult, Severity


class PolicyEvaluator:
    """Evaluates agent-generated cloud infrastructure plans against organizational policies."""

    SENSITIVE_PORTS = {22, 3389, 3306, 5432, 27017, 6379}

    def __init__(
        self,
        required_tags: Optional[Set[str]] = None,
        monthly_budget_ceiling: float = 1000.0,
    ):
        self.required_tags = required_tags or {"Environment", "Owner", "CostCenter"}
        self.monthly_budget_ceiling = monthly_budget_ceiling

    def evaluate_plan(self, plans: List[ResourcePlan]) -> EvaluationResult:
        violations: List[PolicyViolation] = []
        total_cost = 0.0

        for resource in plans:
            total_cost += resource.estimated_monthly_cost
            violations.extend(self._check_tags(resource))
            violations.extend(self._check_iam(resource))
            violations.extend(self._check_security_groups(resource))

        # Check total aggregated cost ceiling
        if total_cost > self.monthly_budget_ceiling:
            violations.append(
                PolicyViolation(
                    rule_id="COST-001",
                    severity=Severity.HIGH,
                    message=f"Total estimated cost ${total_cost:.2f}/mo exceeds budget limit ${self.monthly_budget_ceiling:.2f}/mo",
                    resource_id="plan_total",
                )
            )

        return EvaluationResult(
            is_compliant=len(violations) == 0,
            violations=violations,
            total_estimated_monthly_cost=total_cost,
        )

    def _check_tags(self, resource: ResourcePlan) -> List[PolicyViolation]:
        violations = []
        missing = [t for t in self.required_tags if t not in resource.tags]
        if missing:
            violations.append(
                PolicyViolation(
                    rule_id="TAG-001",
                    severity=Severity.MEDIUM,
                    message=f"Resource {resource.resource_id} is missing mandatory tags: {', '.join(missing)}",
                    resource_id=resource.resource_id,
                )
            )
        return violations

    def _check_iam(self, resource: ResourcePlan) -> List[PolicyViolation]:
        violations = []
        if "iam" in resource.resource_type.lower():
            policy_doc = resource.properties.get("policy_document", {})
            statements = policy_doc.get("Statement", [])
            for stmt in statements:
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                resources = stmt.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]

                if "*" in actions and "*" in resources:
                    violations.append(
                        PolicyViolation(
                            rule_id="IAM-001",
                            severity=Severity.CRITICAL,
                            message=f"IAM policy {resource.resource_id} contains wildcard admin action and resource",
                            resource_id=resource.resource_id,
                        )
                    )
        return violations

    def _check_security_groups(self, resource: ResourcePlan) -> List[PolicyViolation]:
        violations = []
        if "security_group" in resource.resource_type.lower():
            ingress_rules = resource.properties.get("ingress", [])
            for rule in ingress_rules:
                cidr_blocks = rule.get("cidr_blocks", [])
                from_port = rule.get("from_port", 0)
                to_port = rule.get("to_port", 0)

                if "0.0.0.0/0" in cidr_blocks:
                    # Check if exposes sensitive ports
                    exposed = [
                        p for p in self.SENSITIVE_PORTS if from_port <= p <= to_port
                    ]
                    if exposed:
                        violations.append(
                            PolicyViolation(
                                rule_id="NET-001",
                                severity=Severity.HIGH,
                                message=f"Security group {resource.resource_id} allows 0.0.0.0/0 ingress to sensitive port(s): {exposed}",
                                resource_id=resource.resource_id,
                            )
                        )
        return violations
