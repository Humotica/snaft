"""Tests for posture-aware Rule fields and Firewall.applicable_rules()."""

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

from snaft import Firewall
from snaft.firewall import Action, Rule
from snaft.posture import consume_verdict


FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "tibet-cap-bus"
    / "fixtures"
    / "airlock-runtime-verdict.v1.example.json"
)


def _decision_for_mode(mode: str):
    fixtures = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    verdict = next(v for v in fixtures if v["runtime_mode"] == mode)
    return consume_verdict(verdict)


def _trivial_check(agent_id, erin, erachter):
    return True


def test_rule_without_posture_required_always_applies():
    r = Rule(name="plain", description="x", action=Action.ALLOW, check=_trivial_check)
    assert r.applies_under_posture(None) is True
    assert r.applies_under_posture(_decision_for_mode("embedded_online")) is True
    assert r.applies_under_posture(_decision_for_mode("python_fallback")) is True


def test_rule_posture_required_skipped_when_mismatch():
    """Rule requires deny_external_ai_inbound=False → only applies in healthy mode."""
    r = Rule(
        name="healthy-only",
        description="x",
        action=Action.ALLOW,
        check=_trivial_check,
        posture_required={"deny_external_ai_inbound": False},
    )
    # Healthy posture has the switch as False → matches
    healthy = _decision_for_mode("embedded_online")
    assert r.applies_under_posture(healthy) is True
    # Degraded posture has it True → mismatch → skipped
    degraded = _decision_for_mode("python_fallback")
    assert r.applies_under_posture(degraded) is False


def test_rule_with_no_posture_set_applies_conservatively():
    """If posture is None (cold-start) and rule has requirements, apply anyway."""
    r = Rule(
        name="conservative",
        description="x",
        action=Action.ALLOW,
        check=_trivial_check,
        posture_required={"deny_external_ai_inbound": False},
    )
    assert r.applies_under_posture(None) is True


def test_multi_switch_requirement_all_must_match():
    r = Rule(
        name="multi",
        description="x",
        action=Action.ALLOW,
        check=_trivial_check,
        posture_required={
            "deny_external_ai_inbound": False,
            "deny_unsandboxed_execution": False,
        },
    )
    healthy = _decision_for_mode("embedded_online")
    assert r.applies_under_posture(healthy) is True  # both False
    degraded = _decision_for_mode("python_fallback")
    assert r.applies_under_posture(degraded) is False  # both True


def test_allow_iff_posture_builder():
    """Sugar: Rule.allow_iff_posture(... switch, expected)."""
    r = Rule.allow_iff_posture(
        name="external-only-when-healthy",
        description="allow external AI when posture is healthy",
        check=_trivial_check,
        switch="deny_external_ai_inbound",
        expected=False,
    )
    assert r.posture_required == {"deny_external_ai_inbound": False}
    assert r.action == Action.ALLOW
    healthy = _decision_for_mode("embedded_online")
    assert r.applies_under_posture(healthy) is True
    degraded = _decision_for_mode("python_fallback")
    assert r.applies_under_posture(degraded) is False


def test_to_dict_includes_posture_required():
    r = Rule(
        name="x",
        description="x",
        action=Action.ALLOW,
        check=_trivial_check,
        posture_required={"deny_external_ai_inbound": False},
    )
    d = r.to_dict()
    assert d["posture_required"] == {"deny_external_ai_inbound": False}


def test_to_dict_omits_posture_required_when_none():
    r = Rule(name="x", description="x", action=Action.ALLOW, check=_trivial_check)
    d = r.to_dict()
    assert "posture_required" not in d


def test_firewall_applicable_rules_no_posture():
    fw = Firewall()
    initial = fw.applicable_rules()
    # Without posture set, all rules apply (default + poison)
    assert len(initial) == len(fw._rules)


def test_firewall_applicable_rules_filters_dormant():
    fw = Firewall()
    dormant = Rule(
        name="dormant-in-quarantine",
        description="only when healthy",
        action=Action.ALLOW,
        check=_trivial_check,
        posture_required={"deny_external_ai_inbound": False},
    )
    fw.add_rule(dormant)
    # Healthy posture → dormant rule applies
    fw.set_posture(_decision_for_mode("embedded_online"))
    healthy_rules = fw.applicable_rules()
    assert any(r.name == "dormant-in-quarantine" for r in healthy_rules)
    # Quarantine → dormant rule filtered out
    fw.set_posture(_decision_for_mode("python_fallback"))
    degraded_rules = fw.applicable_rules()
    assert not any(r.name == "dormant-in-quarantine" for r in degraded_rules)


def test_firewall_applicable_rules_passes_explicit_posture():
    fw = Firewall()
    dormant = Rule(
        name="conditional",
        description="x",
        action=Action.ALLOW,
        check=_trivial_check,
        posture_required={"deny_external_ai_inbound": False},
    )
    fw.add_rule(dormant)
    # Override active posture by passing explicit one
    healthy = _decision_for_mode("embedded_online")
    rules = fw.applicable_rules(posture=healthy)
    assert any(r.name == "conditional" for r in rules)
    degraded = _decision_for_mode("python_fallback")
    rules = fw.applicable_rules(posture=degraded)
    assert not any(r.name == "conditional" for r in rules)


def test_posture_required_with_unknown_switch_never_matches():
    """If posture_required references a non-existent switch, mismatch (None != False)."""
    r = Rule(
        name="x",
        description="x",
        action=Action.ALLOW,
        check=_trivial_check,
        posture_required={"made_up_switch": False},
    )
    healthy = _decision_for_mode("embedded_online")
    assert r.applies_under_posture(healthy) is False  # getattr returns None, != False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
