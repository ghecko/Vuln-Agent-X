from vulnagentx.agents.logic_bug_agent import LogicBugAgent
from vulnagentx.agents.router_agent import RouterAgent
from vulnagentx.agents.sceptic_agent import ScepticAgent
from vulnagentx.agents.security_agent import SecurityAgent
from vulnagentx.agents.semantic_agent import SemanticAgent
from vulnagentx.core.state import (
    AgentResult,
    CodeLocation,
    Severity,
    SuspiciousRegion,
    TargetType,
    WorkflowState,
)


def _base_state() -> WorkflowState:
    location = CodeLocation(file_path="src/app.py", start_line=10, end_line=10)
    region = SuspiciousRegion(
        location=location,
        reason="command_exec",
        score=0.9,
        snippet="subprocess.run(user_input, shell=True)",
    )
    return WorkflowState(
        run_id="test-run",
        target_type=TargetType.file,
        suspicious_regions=[region],
        retrieved_context={
            "src/app.py:10-10": "subprocess.run(user_input, shell=True)\nquery = 'SELECT * FROM t WHERE id=' + user_id"
        },
    )


def test_router_agent_emits_route_plan() -> None:
    state = _base_state()
    agent = RouterAgent()
    outputs = agent.run(state)

    assert len(outputs) == 1
    assert state.route_plan
    assert "security_agent" in state.route_plan[0].selected_agents


def test_security_agent_detects_injection_surface() -> None:
    state = _base_state()
    outputs = SecurityAgent().run(state)

    issue_types = {item.issue_type for item in outputs}
    assert "command_injection" in issue_types


def test_semantic_agent_returns_structured_results() -> None:
    state = _base_state()
    outputs = SemanticAgent().run(state)

    assert all(item.agent_name == "semantic_agent" for item in outputs)
    assert all(0.0 <= item.confidence <= 1.0 for item in outputs)


def test_logic_bug_agent_can_emit_high_level_logic_alert() -> None:
    state = _base_state()
    state.retrieved_context["src/app.py:10-10"] = "if i <= len(items):\n    return items[i]"

    outputs = LogicBugAgent().run(state)
    issue_types = {item.issue_type for item in outputs}
    assert "off_by_one" in issue_types


def test_sceptic_agent_adds_counter_evidence_for_weak_single_claim() -> None:
    state = _base_state()
    state.agent_outputs["semantic_agent"] = [
        AgentResult(
            agent_name="semantic_agent",
            issue_type="null_dereference",
            claim="possible null dereference",
            confidence=0.50,
            severity=Severity.medium,
            locations=[state.suspicious_regions[0].location],
        )
    ]

    outputs = ScepticAgent().run(state)

    assert outputs
    assert outputs[0].issue_type == "counter_evidence"
    assert state.counter_evidence
