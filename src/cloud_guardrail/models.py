from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class PolicyViolation:
    rule_id: str
    severity: Severity
    message: str
    resource_id: str


@dataclass
class ResourcePlan:
    resource_id: str
    resource_type: str
    tags: Dict[str, str] = field(default_factory=dict)
    properties: Dict[str, Any] = field(default_factory=dict)
    estimated_monthly_cost: float = 0.0


@dataclass
class EvaluationResult:
    is_compliant: bool
    violations: List[PolicyViolation] = field(default_factory=list)
    total_estimated_monthly_cost: float = 0.0
