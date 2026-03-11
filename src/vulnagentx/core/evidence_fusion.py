from __future__ import annotations

from collections import Counter, defaultdict

from vulnagentx.core.state import AgentResult, EvidenceItem, Finding, Severity, WorkflowState

_AGENT_WEIGHTS: dict[str, float] = {
    "semantic_agent": 0.33,
    "security_agent": 0.40,
    "logic_bug_agent": 0.27,
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}

_FIX_HINTS: dict[str, str] = {
    "command_injection": "Avoid shell command composition; use parameterized APIs and strict allowlists.",
    "sql_injection": "Use prepared statements/ORM parameter binding; remove direct string concatenation.",
    "buffer_overflow": "Replace unsafe C string APIs with bounds-checked alternatives.",
    "path_traversal": "Canonicalize and validate paths against an allowlisted root.",
    "null_dereference": "Add explicit null/None guard and fail-safe handling before dereference.",
    "unchecked_return": "Validate return values and handle allocation/open failures.",
    "off_by_one": "Re-check loop boundary and convert <= to < where required.",
    "division_by_zero": "Guard denominator with zero-check before division.",
    "missing_authz_check": "Insert explicit authorization/ownership check before sensitive operation.",
}


def _loc_key(file_path: str, start_line: int, end_line: int) -> str:
    return f"{file_path}:{start_line}-{end_line}"


def _max_severity(results: list[AgentResult]) -> Severity:
    return max((item.severity for item in results), key=lambda sev: _SEVERITY_RANK[sev])


def fuse_evidence(state: WorkflowState, min_confidence: float = 0.35) -> WorkflowState:
    grouped: dict[tuple[str, str], list[AgentResult]] = defaultdict(list)

    for agent_name, results in state.agent_outputs.items():
        if agent_name in {"router_agent", "sceptic_agent"}:
            continue
        for result in results:
            if not result.supports_issue or not result.locations:
                continue
            for loc in result.locations:
                grouped[(_loc_key(loc.file_path, loc.start_line, loc.end_line), result.issue_type)].append(result)

    sceptic_scores: dict[str, float] = defaultdict(float)
    for result in state.agent_outputs.get("sceptic_agent", []):
        for loc in result.locations:
            key = _loc_key(loc.file_path, loc.start_line, loc.end_line)
            sceptic_scores[key] = max(sceptic_scores[key], result.confidence)

    verification_scores: dict[str, float] = defaultdict(float)
    global_verification_boost = 0.0
    for verification_result in state.verification_results:
        if verification_result.location is None:
            global_verification_boost = max(global_verification_boost, verification_result.signal_score)
            continue
        key = _loc_key(
            verification_result.location.file_path,
            verification_result.location.start_line,
            verification_result.location.end_line,
        )
        verification_scores[key] = max(verification_scores[key], verification_result.signal_score)

    findings: list[Finding] = []

    for (location_key, issue_type), results in grouped.items():
        first_loc = results[0].locations[0]
        weighted_score = 0.0
        total_weight = 0.0
        for result in results:
            weight = _AGENT_WEIGHTS.get(result.agent_name, 0.20)
            weighted_score += weight * result.confidence
            total_weight += weight

        if total_weight == 0:
            continue

        base_score = weighted_score / total_weight
        agent_count = len({result.agent_name for result in results})
        agreement_bonus = min(0.15, 0.05 * max(0, agent_count - 1))
        penalty = sceptic_scores.get(location_key, 0.0) * 0.35
        verification_boost = verification_scores.get(location_key, 0.0) * 0.25
        final_score = max(
            0.0,
            min(1.0, base_score + agreement_bonus + verification_boost + global_verification_boost * 0.10 - penalty),
        )

        if final_score < min_confidence:
            continue

        claims = [result.claim for result in results]
        claim_digest = "; ".join(claims[:2])

        cwe_counter = Counter(item.optional_cwe for item in results if item.optional_cwe)
        cwe = cwe_counter.most_common(1)[0][0] if cwe_counter else None

        evidence_chain: list[EvidenceItem] = []
        for result in results:
            evidence_chain.extend(result.evidence)

        verification_signal = verification_scores.get(location_key)
        if verification_signal is not None and verification_signal > 0:
            evidence_chain.append(
                EvidenceItem(
                    source="verification",
                    summary=f"Verification signal score={verification_signal:.2f}",
                    location=first_loc,
                    raw={"signal_score": verification_signal},
                )
            )

        counter_evidence = [
            item
            for item in state.counter_evidence
            if item.location is not None
            and _loc_key(item.location.file_path, item.location.start_line, item.location.end_line)
            == location_key
        ]

        findings.append(
            Finding(
                issue_type=issue_type,
                location=first_loc,
                evidence_summary=claim_digest,
                confidence=round(final_score, 4),
                severity=_max_severity(results),
                optional_cwe=cwe,
                fix_hint=_FIX_HINTS.get(issue_type, "Add targeted guards and tests for this risky path."),
                source_agents=sorted({result.agent_name for result in results}),
                evidence_chain=evidence_chain,
                counter_evidence=counter_evidence,
            )
        )

    findings.sort(key=lambda item: item.confidence, reverse=True)
    state.final_findings = findings
    state.metrics["final_findings"] = float(len(findings))
    state.add_log(stage="evidence_fusion", message="Evidence fusion complete", findings=len(findings))
    return state
