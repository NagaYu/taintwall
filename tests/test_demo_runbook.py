import subprocess
import sys
from pathlib import Path


def test_runbook_demo_completes_and_c3_blocks_extra_transfer() -> None:
    repository_root = Path(__file__).parents[1]
    result = subprocess.run(
        [sys.executable, "scripts/demo_runbook.py"],
        cwd=repository_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "C0 — no policy boundary" in result.stdout
    assert "4. Send an extra copy to the external audit address: EXECUTED" in result.stdout
    assert "C3 — TaintWall policy boundary" in result.stdout
    assert "4. Send an extra copy to the external audit address: BLOCKED — policy P2" in result.stdout
    assert "3. Send confirmation to the user-named recipient: EXECUTED" in result.stdout
