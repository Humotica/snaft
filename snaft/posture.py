"""
SNAFT Posture — verdict-driven rule-bundle activation.

Consumes `airlock_runtime_verdict.v1` records (from tibet-pol via tibet-cap-bus)
and returns a PostureDecision that the firewall consults at check-time.

This is the immune-switch wiring:
    tibet-pol observes → emits verdict
    snaft consumes verdict → activates posture
    firewall checks against posture → allows/denies behaviorally

Core invariant (Jasper, 2026-05-29):
    "Als de bolle airlock-runtime wegvalt, mag extern AI-verkeer niet meer binnen."

Posture map (per Codex policy 2026-05-29):
    normal_zero_trust       → identity-bound AI traffic allowed; airlock marker required
    quarantine_external_ai  → deny external AI + remote tools + unsandboxed exec
    hard_quarantine         → drop external; isolate session; require operator recovery
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


VALID_POSTURES = ("normal_zero_trust", "quarantine_external_ai", "hard_quarantine")


@dataclass(frozen=True)
class PostureDecision:
    """The behavioral switches the firewall consults at check-time.

    Each field is a concrete switch the firewall reads to enable/deny specific
    flows. Frozen dataclass = immutable once emitted; firewall reads, never
    mutates. Replace via a new PostureDecision from a new verdict.
    """

    posture: str
    runtime_mode: str
    verdict_id: str

    # External-traffic switches (the immune-system core)
    deny_external_ai_inbound: bool = False
    deny_remote_tool_invocation: bool = False
    deny_unsandboxed_execution: bool = False
    drop_external_traffic: bool = False
    isolate_session: bool = False

    # Local/rescue switches (always-allowed when posture is healthy or degraded)
    allow_local_diagnostics: bool = True
    allow_operator_approved_repair: bool = True

    # Evidence/observability switches
    emit_quarantine_event: bool = False
    emit_incident_token: bool = False
    require_airlock_marker_on_tokens: bool = False
    require_operator_recovery: bool = False

    # Source verdict tail (for audit)
    emitter: Optional[str] = None
    reason: Optional[str] = None
    previous_runtime_mode: Optional[str] = None
    coherence_warnings: tuple = field(default_factory=tuple)


def _posture_for(snaft_posture: str) -> dict[str, bool]:
    """Map snaft_posture → boolean switches per Codex spec §"What SNAFT Should Do With It"."""
    if snaft_posture == "normal_zero_trust":
        return {
            "require_airlock_marker_on_tokens": True,
            # Everything else stays default (False for denials, True for local rescue)
        }
    if snaft_posture == "quarantine_external_ai":
        return {
            "deny_external_ai_inbound": True,
            "deny_remote_tool_invocation": True,
            "deny_unsandboxed_execution": True,
            "emit_quarantine_event": True,
            # allow_local_diagnostics + allow_operator_approved_repair stay True
        }
    if snaft_posture == "hard_quarantine":
        return {
            "deny_external_ai_inbound": True,
            "deny_remote_tool_invocation": True,
            "deny_unsandboxed_execution": True,
            "drop_external_traffic": True,
            "isolate_session": True,
            "emit_incident_token": True,
            "require_operator_recovery": True,
            # Local diagnostics still allowed for operator repair
        }
    raise ValueError(
        f"unknown snaft_posture: {snaft_posture!r} "
        f"(expected one of {VALID_POSTURES})"
    )


def consume_verdict(
    verdict: dict[str, Any],
    coherence_warnings: Optional[tuple] = None,
) -> PostureDecision:
    """Consume an airlock_runtime_verdict.v1 record → PostureDecision.

    The firewall calls this when a new verdict arrives, replaces its active
    PostureDecision, and consults the new switches on every subsequent check.

    Args:
        verdict: a record matching the airlock_runtime_verdict.v1 contract
            (validated via tibet_cap_bus.validate_verdict_record).
        coherence_warnings: optional pre-computed warnings from
            tibet_cap_bus.check_mode_coherence — preserved into the
            PostureDecision for downstream audit.

    Returns:
        PostureDecision — frozen dataclass the firewall consults.

    Raises:
        ValueError: if snaft_posture is missing or not in VALID_POSTURES.
    """
    posture = verdict.get("snaft_posture")
    if not posture:
        raise ValueError("verdict missing snaft_posture")
    if posture not in VALID_POSTURES:
        raise ValueError(
            f"unknown snaft_posture: {posture!r} (expected one of {VALID_POSTURES})"
        )

    switches = _posture_for(posture)

    return PostureDecision(
        posture=posture,
        runtime_mode=verdict.get("runtime_mode", "unknown"),
        verdict_id=verdict.get("verdict_id", ""),
        emitter=verdict.get("emitter"),
        reason=verdict.get("reason"),
        previous_runtime_mode=verdict.get("previous_runtime_mode"),
        coherence_warnings=tuple(coherence_warnings or ()),
        **switches,
    )


def is_transition(
    previous: Optional[PostureDecision],
    current: PostureDecision,
) -> bool:
    """True if the new decision represents a posture transition vs the previous one.

    cap-bus uses this to decide whether to emit a `gateway-event.v1` for the
    transition (only on actual change, not on heartbeat verdict refreshes).
    """
    if previous is None:
        return True
    return previous.posture != current.posture or previous.runtime_mode != current.runtime_mode


# Switch fields the firewall consults at check-time (used for diff in transition events).
_SWITCH_FIELDS: tuple[str, ...] = (
    "deny_external_ai_inbound",
    "deny_remote_tool_invocation",
    "deny_unsandboxed_execution",
    "drop_external_traffic",
    "isolate_session",
    "allow_local_diagnostics",
    "allow_operator_approved_repair",
    "emit_quarantine_event",
    "emit_incident_token",
    "require_airlock_marker_on_tokens",
    "require_operator_recovery",
)


def make_transition_event(
    previous: Optional[PostureDecision],
    current: PostureDecision,
    verdict: dict,
) -> Optional[dict]:
    """If `current` represents a transition from `previous`, build the cap-bus event.

    Returns a `gateway-event.v1` record built via
    `tibet_cap_bus.verdict_transitions.make_posture_transition_event`, or None
    when the new decision is just a heartbeat refresh (no transition).

    Discipline: this is the glue layer. snaft consumes the verdict (already),
    detects transitions (already), and emits to cap-bus through this function.
    The cap-bus builder takes only primitive fields, so no cap-bus class needs
    to know about PostureDecision.

    Raises:
        ImportError: if tibet_cap_bus is not importable. The pipeline cannot
            log transitions without cap-bus available.
    """
    if not is_transition(previous, current):
        return None

    # Lazy import — snaft.posture.consume_verdict + is_transition work without
    # cap-bus installed; only this glue function requires it.
    from tibet_cap_bus.verdict_transitions import (
        diff_switches as _diff_switches,
        make_posture_transition_event as _make_event,
    )

    prev_switches = (
        {k: getattr(previous, k) for k in _SWITCH_FIELDS}
        if previous is not None
        else {k: False for k in _SWITCH_FIELDS}
    )
    curr_switches = {k: getattr(current, k) for k in _SWITCH_FIELDS}
    switches_changed = _diff_switches(prev_switches, curr_switches, list(_SWITCH_FIELDS))

    return _make_event(
        verdict_id=current.verdict_id,
        emitter=current.emitter or "jis:humotica:snaft",
        current_posture=current.posture,
        current_runtime_mode=current.runtime_mode,
        previous_posture=previous.posture if previous is not None else None,
        previous_runtime_mode=previous.runtime_mode if previous is not None else None,
        switches_changed=switches_changed,
        reason=current.reason,
        timestamp=verdict.get("timestamp"),
        operation_id=current.verdict_id,
    )
