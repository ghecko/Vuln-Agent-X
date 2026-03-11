from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class TargetType(str, Enum):
    repository = "repository"
    diff = "diff"
    commit = "commit"
    file = "file"
    function = "function"


class CodeLocation(BaseModel):
    file_path: str
    start_line: int = Field(default=1, ge=1)
    end_line: int = Field(default=1, ge=1)


class SuspiciousRegion(BaseModel):
    location: CodeLocation
    reason: str
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    snippet: str = ""


class EvidenceItem(BaseModel):
    source: str
    summary: str
    location: CodeLocation | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class AgentResult(BaseModel):
    agent_name: str
    issue_type: str
    claim: str
    evidence: list[EvidenceItem] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: Severity = Severity.low
    optional_cwe: str | None = None
    locations: list[CodeLocation] = Field(default_factory=list)
    notes: str = ""
    supports_issue: bool = True


class VerificationResult(BaseModel):
    location: CodeLocation | None = None
    executed: bool = False
    passed: bool | None = None
    summary: str = ""
    signal_score: float = Field(default=0.0, ge=0.0, le=1.0)
    task_results: list[dict[str, Any]] = Field(default_factory=list)


class Finding(BaseModel):
    issue_type: str
    location: CodeLocation
    evidence_summary: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    optional_cwe: str | None = None
    fix_hint: str = ""
    source_agents: list[str] = Field(default_factory=list)
    evidence_chain: list[EvidenceItem] = Field(default_factory=list)
    counter_evidence: list[EvidenceItem] = Field(default_factory=list)


class LogEvent(BaseModel):
    stage: str
    message: str
    timestamp: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RoutePlan(BaseModel):
    location: CodeLocation
    selected_agents: list[str] = Field(default_factory=list)
    rationale: str = ""


class EscalationStep(BaseModel):
    location: CodeLocation
    action: str
    rationale: str


class WorkflowState(BaseModel):
    run_id: str
    repo_path: str | None = None
    diff_text: str | None = None
    target_type: TargetType = TargetType.repository
    suspicious_regions: list[SuspiciousRegion] = Field(default_factory=list)
    retrieved_context: dict[str, str] = Field(default_factory=dict)
    graph_neighbors: dict[str, list[str]] = Field(default_factory=dict)
    route_plan: list[RoutePlan] = Field(default_factory=list)
    escalation_plan: list[EscalationStep] = Field(default_factory=list)
    agent_outputs: dict[str, list[AgentResult]] = Field(default_factory=dict)
    counter_evidence: list[EvidenceItem] = Field(default_factory=list)
    verification_results: list[VerificationResult] = Field(default_factory=list)
    final_findings: list[Finding] = Field(default_factory=list)
    metrics: dict[str, float] = Field(default_factory=dict)
    logs: list[LogEvent] = Field(default_factory=list)

    def add_log(self, stage: str, message: str, **metadata: Any) -> None:
        self.logs.append(LogEvent(stage=stage, message=message, metadata=metadata))
