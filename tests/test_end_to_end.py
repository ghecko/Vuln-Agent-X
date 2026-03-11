from pathlib import Path

from vulnagentx.core.workflow import VulnAgentWorkflow


def test_workflow_end_to_end_on_toy_repo(tmp_path: Path) -> None:
    source = tmp_path / "vuln.py"
    source.write_text(
        """
import subprocess

def run(user_input):
    subprocess.run(user_input, shell=True)
    query = "SELECT * FROM users WHERE id=" + user_input
    return query
""".strip(),
        encoding="utf-8",
    )

    workflow = VulnAgentWorkflow()
    state = workflow.run(repo_path=str(tmp_path))

    assert state.final_findings
    top = state.final_findings[0]
    assert top.issue_type
    assert top.location.file_path == "vuln.py"
    assert 0.0 <= top.confidence <= 1.0
    assert top.evidence_chain
    assert state.logs
    stages = {item.stage for item in state.logs}
    assert "screening" in stages
    assert "evidence_fusion" in stages
