"""Tests for snaft/posture.py — verdict.v1 consumer + rule-bundle activation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from snaft.posture import (
    VALID_POSTURES,
    PostureDecision,
    consume_verdict,
    is_transition,
)


# Re-use the verdict.v1 fixtures from tibet-cap-bus
FIXTURE_PATH = (
    Path(__file__).parent.parent.parent
    / "tibet-cap-bus"
    / "fixtures"
    / "airlock-runtime-verdict.v1.example.json"
)


def _load_fixtures():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_consume_embedded_online_normal_zero_trust():
    fixtures = _load_fixtures()
    verdict = next(v for v in fixtures if v["runtime_mode"] == "embedded_online")
    decision = consume_verdict(verdict)

    assert decision.posture == "normal_zero_trust"
    assert decision.runtime_mode == "embedded_online"
    # Hardened: airlock marker required, no external denials
    assert decision.require_airlock_marker_on_tokens is True
    assert decision.deny_external_ai_inbound is False
    assert decision.deny_remote_tool_invocation is False
    assert decision.deny_unsandboxed_execution is False
    # Local rescue still available
    assert decision.allow_local_diagnostics is True
    assert decision.allow_operator_approved_repair is True


def test_consume_kernel_online_normal_zero_trust():
    fixtures = _load_fixtures()
    verdict = next(v for v in fixtures if v["runtime_mode"] == "kernel_online")
    decision = consume_verdict(verdict)

    assert decision.posture == "normal_zero_trust"
    assert decision.runtime_mode == "kernel_online"
    assert decision.require_airlock_marker_on_tokens is True
    assert decision.deny_external_ai_inbound is False


def test_consume_python_fallback_quarantines_external_ai():
    fixtures = _load_fixtures()
    verdict = next(v for v in fixtures if v["runtime_mode"] == "python_fallback")
    decision = consume_verdict(verdict)

    assert decision.posture == "quarantine_external_ai"
    assert decision.runtime_mode == "python_fallback"
    # The invariant: bolle weg → extern AI deny
    assert decision.deny_external_ai_inbound is True
    assert decision.deny_remote_tool_invocation is True
    assert decision.deny_unsandboxed_execution is True
    assert decision.emit_quarantine_event is True
    # Local rescue still allowed
    assert decision.allow_local_diagnostics is True
    assert decision.allow_operator_approved_repair is True
    # Not hard quarantine yet
    assert decision.drop_external_traffic is False
    assert decision.isolate_session is False


def test_consume_offline_hard_quarantine():
    fixtures = _load_fixtures()
    verdict = next(v for v in fixtures if v["runtime_mode"] == "offline")
    decision = consume_verdict(verdict)

    assert decision.posture == "hard_quarantine"
    assert decision.runtime_mode == "offline"
    assert decision.deny_external_ai_inbound is True
    assert decision.drop_external_traffic is True
    assert decision.isolate_session is True
    assert decision.emit_incident_token is True
    assert decision.require_operator_recovery is True
    # Local diagnostics still on for operator repair
    assert decision.allow_local_diagnostics is True


def test_decision_is_frozen():
    """PostureDecision is immutable — replace via new consume_verdict, never mutate."""
    fixtures = _load_fixtures()
    verdict = next(v for v in fixtures if v["runtime_mode"] == "embedded_online")
    decision = consume_verdict(verdict)
    with pytest.raises(Exception):  # FrozenInstanceError or dataclasses.FrozenInstanceError
        decision.deny_external_ai_inbound = True  # type: ignore[misc]


def test_unknown_posture_raises():
    bad = {"snaft_posture": "vibes_only", "runtime_mode": "embedded_online", "verdict_id": "v1"}
    with pytest.raises(ValueError, match="unknown snaft_posture"):
        consume_verdict(bad)


def test_missing_posture_raises():
    bad = {"runtime_mode": "embedded_online", "verdict_id": "v1"}
    with pytest.raises(ValueError, match="missing snaft_posture"):
        consume_verdict(bad)


def test_coherence_warnings_preserved():
    fixtures = _load_fixtures()
    verdict = next(v for v in fixtures if v["runtime_mode"] == "embedded_online")
    decision = consume_verdict(verdict, coherence_warnings=("test-warning-A", "test-warning-B"))
    assert decision.coherence_warnings == ("test-warning-A", "test-warning-B")


def test_is_transition_first_decision():
    fixtures = _load_fixtures()
    verdict = next(v for v in fixtures if v["runtime_mode"] == "embedded_online")
    decision = consume_verdict(verdict)
    assert is_transition(None, decision) is True


def test_is_transition_no_change():
    fixtures = _load_fixtures()
    verdict = next(v for v in fixtures if v["runtime_mode"] == "embedded_online")
    decision_a = consume_verdict(verdict)
    decision_b = consume_verdict(verdict)
    assert is_transition(decision_a, decision_b) is False


def test_is_transition_posture_change_detected():
    fixtures = _load_fixtures()
    healthy = next(v for v in fixtures if v["runtime_mode"] == "embedded_online")
    degraded = next(v for v in fixtures if v["runtime_mode"] == "python_fallback")
    d_healthy = consume_verdict(healthy)
    d_degraded = consume_verdict(degraded)
    assert is_transition(d_healthy, d_degraded) is True
    # And back (recovery)
    assert is_transition(d_degraded, d_healthy) is True


def test_all_postures_have_mapping():
    """Sanity: every VALID_POSTURE has a defined switch-mapping (no crash)."""
    for posture in VALID_POSTURES:
        verdict = {
            "snaft_posture": posture,
            "runtime_mode": "test",
            "verdict_id": f"test-{posture}",
        }
        decision = consume_verdict(verdict)
        assert decision.posture == posture


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
