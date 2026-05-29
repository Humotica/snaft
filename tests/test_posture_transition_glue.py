"""Tests for the snaft → cap-bus glue: make_transition_event."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make tibet_cap_bus importable
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2] / "tibet-cap-bus" / "src"),
)

from snaft.posture import (
    consume_verdict,
    is_transition,
    make_transition_event,
)
from tibet_cap_bus import POSTURE_TRANSITION_INTENT, validate_gateway_event_record


FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "tibet-cap-bus"
    / "fixtures"
    / "airlock-runtime-verdict.v1.example.json"
)


def _fixtures():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_no_transition_returns_none():
    fixtures = _fixtures()
    verdict = next(v for v in fixtures if v["runtime_mode"] == "embedded_online")
    decision = consume_verdict(verdict)
    event = make_transition_event(decision, decision, verdict)
    assert event is None


def test_cold_start_produces_event():
    fixtures = _fixtures()
    verdict = next(v for v in fixtures if v["runtime_mode"] == "embedded_online")
    decision = consume_verdict(verdict)
    event = make_transition_event(None, decision, verdict)
    assert event is not None
    assert event["payload"]["cold_start"] is True
    assert event["payload"]["previous"]["posture"] is None
    assert event["intent"] == POSTURE_TRANSITION_INTENT


def test_degradation_emits_valid_gateway_event():
    fixtures = _fixtures()
    healthy_v = next(v for v in fixtures if v["runtime_mode"] == "embedded_online")
    degraded_v = next(v for v in fixtures if v["runtime_mode"] == "python_fallback")
    healthy = consume_verdict(healthy_v)
    degraded = consume_verdict(degraded_v)
    event = make_transition_event(healthy, degraded, degraded_v)
    assert event is not None
    errors = validate_gateway_event_record(event)
    assert errors == [], f"validation failed: {errors}"
    assert event["payload"]["current"]["posture"] == "quarantine_external_ai"
    assert event["payload"]["previous"]["posture"] == "normal_zero_trust"


def test_switches_changed_captures_invariant_flip():
    """Healthy -> python_fallback: deny_external_ai_inbound flips ON."""
    fixtures = _fixtures()
    healthy_v = next(v for v in fixtures if v["runtime_mode"] == "embedded_online")
    degraded_v = next(v for v in fixtures if v["runtime_mode"] == "python_fallback")
    healthy = consume_verdict(healthy_v)
    degraded = consume_verdict(degraded_v)
    event = make_transition_event(healthy, degraded, degraded_v)
    changed = event["payload"]["switches_changed"]
    assert "deny_external_ai_inbound" in changed
    assert "deny_remote_tool_invocation" in changed
    assert "deny_unsandboxed_execution" in changed
    assert "emit_quarantine_event" in changed
    # Local rescue stayed ON both sides — should NOT appear
    assert "allow_local_diagnostics" not in changed
    assert "allow_operator_approved_repair" not in changed


def test_recovery_emits_event_with_reverse_diff():
    """python_fallback -> embedded_online: same switches flip OFF."""
    fixtures = _fixtures()
    degraded_v = next(v for v in fixtures if v["runtime_mode"] == "python_fallback")
    healthy_v = next(v for v in fixtures if v["runtime_mode"] == "embedded_online")
    degraded = consume_verdict(degraded_v)
    healthy = consume_verdict(healthy_v)
    event = make_transition_event(degraded, healthy, healthy_v)
    assert event is not None
    changed = event["payload"]["switches_changed"]
    assert "deny_external_ai_inbound" in changed
    # And airlock-marker requirement comes back ON
    assert "require_airlock_marker_on_tokens" in changed


def test_offline_transition_emits_incident_switches():
    fixtures = _fixtures()
    fallback_v = next(v for v in fixtures if v["runtime_mode"] == "python_fallback")
    offline_v = next(v for v in fixtures if v["runtime_mode"] == "offline")
    fallback = consume_verdict(fallback_v)
    offline = consume_verdict(offline_v)
    event = make_transition_event(fallback, offline, offline_v)
    changed = event["payload"]["switches_changed"]
    assert "drop_external_traffic" in changed
    assert "isolate_session" in changed
    assert "emit_incident_token" in changed
    assert "require_operator_recovery" in changed


def test_transition_event_carries_verdict_id_as_operation_id():
    fixtures = _fixtures()
    verdict = next(v for v in fixtures if v["runtime_mode"] == "embedded_online")
    decision = consume_verdict(verdict)
    event = make_transition_event(None, decision, verdict)
    assert event["operation_id"] == verdict["verdict_id"]


def test_is_transition_and_make_transition_event_consistent():
    """make_transition_event returns None iff is_transition returns False."""
    fixtures = _fixtures()
    pairs = [
        ("embedded_online", "embedded_online", False),
        ("embedded_online", "kernel_online", True),
        ("embedded_online", "python_fallback", True),
        ("python_fallback", "offline", True),
        ("offline", "embedded_online", True),
    ]
    for prev_mode, curr_mode, expected_transition in pairs:
        prev_v = next(v for v in fixtures if v["runtime_mode"] == prev_mode)
        curr_v = next(v for v in fixtures if v["runtime_mode"] == curr_mode)
        prev_d = consume_verdict(prev_v)
        curr_d = consume_verdict(curr_v)
        assert is_transition(prev_d, curr_d) is expected_transition
        event = make_transition_event(prev_d, curr_d, curr_v)
        assert (event is not None) is expected_transition


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
