"""Tests for SNAFT-DESTRUCT-001: always-blocked shell patterns regardless of posture."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2] / "tibet-cap-bus" / "src"),
)

from snaft import Firewall
from snaft.firewall import _check_destructive_command
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


# Pattern detection — pure check fn


@pytest.mark.parametrize("payload", [
    "rm -rf /",
    "rm -rf /*",
    "rm -rf /etc",
    "rm --recursive --force /",
    "dd if=/dev/zero of=/dev/sda bs=1M",
    "dd if=/dev/urandom of=/dev/nvme0n1",
    "mkfs.ext4 /dev/sdb",
    "mkfs /dev/sda1",
    "wipefs -a /dev/sdb",
    "cat /dev/urandom > /dev/sda",
    "chmod -R 000 /etc",
    "chmod -R 777 /usr",
    "chown -R nobody /var",
    ":(){:|:&};:",  # fork bomb
    "systemctl poweroff",
    "shutdown -h now",
    "init 0",
])
def test_destructive_patterns_detected(payload):
    """Each pattern triggers the check regardless of erachter context."""
    assert _check_destructive_command("agent", payload, "any-intent") is True


@pytest.mark.parametrize("payload", [
    "rm file.txt",
    "rm -rf ./build",
    "rm -rf /tmp/safe-scratch",  # path under /tmp is conventionally safe
    "dd if=input.bin of=output.bin",
    "mkfs --help",
    "echo hello",
    "ls -la /etc",
    "chmod 644 README.md",
])
def test_benign_commands_not_triggered(payload):
    """Common safe shell usage does NOT trigger destructive detection."""
    # Note: 'rm -rf /tmp/...' might be considered safe; if regex catches it,
    # adjust the pattern. Current pattern requires `/`, `/*`, or specific
    # root-level dirs — /tmp/... should pass.
    result = _check_destructive_command("agent", payload, "any-intent")
    assert result is False, f"benign payload triggered destructive check: {payload!r}"


# Firewall integration — block fires regardless of posture


def test_destruct_rule_present_in_firewall():
    fw = Firewall()
    rule_names = [r.name for r in fw._rules]
    assert "SNAFT-DESTRUCT-001" in rule_names


def test_destruct_rule_is_priority_zero():
    """Highest priority: checked before any other poison rule."""
    fw = Firewall()
    destruct = next(r for r in fw._rules if r.name == "SNAFT-DESTRUCT-001")
    assert destruct.priority == 0


def test_destruct_rule_is_immutable_and_poison():
    fw = Firewall()
    destruct = next(r for r in fw._rules if r.name == "SNAFT-DESTRUCT-001")
    assert destruct.immutable is True
    assert destruct._poison is True
    # And critically: posture_required is None — ALWAYS applies
    assert destruct.posture_required is None


def test_destruct_rule_applies_under_healthy_posture():
    """Even when the runtime is fully healthy, the rule still fires."""
    fw = Firewall()
    fw.set_posture(_decision_for_mode("embedded_online"))
    rules = fw.applicable_rules()
    assert any(r.name == "SNAFT-DESTRUCT-001" for r in rules)


def test_destruct_rule_applies_under_quarantine_posture():
    fw = Firewall()
    fw.set_posture(_decision_for_mode("python_fallback"))
    rules = fw.applicable_rules()
    assert any(r.name == "SNAFT-DESTRUCT-001" for r in rules)


def test_destruct_rule_applies_under_hard_quarantine():
    fw = Firewall()
    fw.set_posture(_decision_for_mode("offline"))
    rules = fw.applicable_rules()
    assert any(r.name == "SNAFT-DESTRUCT-001" for r in rules)


def test_destruct_blocks_in_evaluate_even_healthy():
    """End-to-end: payload with rm -rf / gets blocked by fw.check() under healthy posture."""
    fw = Firewall()
    fw.set_posture(_decision_for_mode("embedded_online"))
    allowed, token, trust = fw.check("test-agent", "rm -rf /", "cleanup workspace")
    assert allowed is False
    # Provenance should reference the destruct rule
    assert "DESTRUCT" in token.rule_name or "SNAFT-DESTRUCT" in token.rule_name


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
