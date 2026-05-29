"""End-to-end test: verdict.v1 -> PostureDecision -> Firewall.precheck_posture()."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make tibet_cap_bus importable for cross-package validation flow
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2] / "tibet-cap-bus" / "src"),
)

from snaft import Firewall
from snaft.posture import consume_verdict


FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "tibet-cap-bus"
    / "fixtures"
    / "airlock-runtime-verdict.v1.example.json"
)


def _decision_for_mode(mode: str):
    """Helper: load a fixture and consume it into a PostureDecision."""
    fixtures = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    verdict = next(v for v in fixtures if v["runtime_mode"] == mode)
    return consume_verdict(verdict)


def test_no_posture_set_default_safe():
    fw = Firewall()
    assert fw.get_posture() is None
    allowed, reason = fw.precheck_posture({"origin": "external_ai"})
    assert allowed is True
    assert "no posture set" in reason


def test_normal_zero_trust_allows_external_ai():
    """When posture is healthy, external AI traffic gets through precheck
    (still subject to regular rules in evaluate())."""
    fw = Firewall()
    fw.set_posture(_decision_for_mode("embedded_online"))
    allowed, reason = fw.precheck_posture({"origin": "external_ai"})
    assert allowed is True
    assert "normal_zero_trust" in reason


def test_quarantine_blocks_external_ai_inbound():
    """python_fallback mode: invariant kicks in. External AI denied at precheck."""
    fw = Firewall()
    fw.set_posture(_decision_for_mode("python_fallback"))
    allowed, reason = fw.precheck_posture({"origin": "external_ai"})
    assert allowed is False
    assert "deny_external_ai_inbound" in reason
    assert "quarantine_external_ai" in reason


def test_quarantine_blocks_remote_tool_invocation():
    fw = Firewall()
    fw.set_posture(_decision_for_mode("python_fallback"))
    allowed, reason = fw.precheck_posture(
        {"origin": "internal", "invokes_remote_tool": True}
    )
    assert allowed is False
    assert "deny_remote_tool_invocation" in reason


def test_quarantine_blocks_unsandboxed_execution():
    fw = Firewall()
    fw.set_posture(_decision_for_mode("python_fallback"))
    allowed, reason = fw.precheck_posture(
        {"origin": "internal", "sandboxed": False}
    )
    assert allowed is False
    assert "deny_unsandboxed_execution" in reason


def test_quarantine_allows_local_diagnostics():
    """Even in quarantine, internal sandboxed operations get through precheck."""
    fw = Firewall()
    fw.set_posture(_decision_for_mode("python_fallback"))
    allowed, reason = fw.precheck_posture(
        {"origin": "internal", "sandboxed": True, "invokes_remote_tool": False}
    )
    assert allowed is True
    assert "precheck pass" in reason


def test_hard_quarantine_drops_external_traffic():
    """offline mode: hardest. drop_external_traffic + isolate_session both ON."""
    fw = Firewall()
    fw.set_posture(_decision_for_mode("offline"))
    allowed, reason = fw.precheck_posture({"origin": "external"})
    assert allowed is False
    # drop_external_traffic fires first
    assert "drop_external_traffic" in reason
    assert "hard_quarantine" in reason


def test_hard_quarantine_still_blocks_external_ai():
    fw = Firewall()
    fw.set_posture(_decision_for_mode("offline"))
    allowed, reason = fw.precheck_posture({"origin": "external_ai"})
    assert allowed is False


def test_hard_quarantine_allows_operator_repair_path():
    """offline mode keeps local diagnostics on for operator repair."""
    fw = Firewall()
    fw.set_posture(_decision_for_mode("offline"))
    allowed, reason = fw.precheck_posture({"origin": "internal", "sandboxed": True})
    assert allowed is True


def test_set_and_clear_posture_round_trip():
    fw = Firewall()
    decision = _decision_for_mode("python_fallback")
    fw.set_posture(decision)
    assert fw.get_posture() is decision
    fw.clear_posture()
    assert fw.get_posture() is None
    # And now external_ai is precheck-allowed again
    allowed, _ = fw.precheck_posture({"origin": "external_ai"})
    assert allowed is True


def test_posture_swap_changes_behavior_immediately():
    fw = Firewall()
    # Start healthy
    fw.set_posture(_decision_for_mode("embedded_online"))
    allowed_before, _ = fw.precheck_posture({"origin": "external_ai"})
    assert allowed_before is True
    # Degrade: same Firewall instance, new posture, gedrag flips
    fw.set_posture(_decision_for_mode("python_fallback"))
    allowed_after, _ = fw.precheck_posture({"origin": "external_ai"})
    assert allowed_after is False


def test_end_to_end_verdict_to_precheck():
    """The full keten: raw verdict.v1 dict -> consume -> set_posture -> precheck."""
    fixtures = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    degraded_verdict = next(v for v in fixtures if v["runtime_mode"] == "python_fallback")
    decision = consume_verdict(degraded_verdict)

    fw = Firewall()
    fw.set_posture(decision)

    # The invariant holds end-to-end:
    blocked, reason = fw.precheck_posture({"origin": "external_ai"})
    assert blocked is False, "external AI inbound MUST be blocked in python_fallback"
    assert "deny_external_ai_inbound" in reason


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
