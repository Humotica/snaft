"""
SNAFT Firewall — Semantic, intent-aware behavioral firewall for AI agents.

Not a guardrail. An immune system.

Principles:
    1. Default DENY — no rule match = blocked
    2. Fail CLOSED — exception in rule check = blocked
    3. Immutable core — OWASP rules cannot be removed, ever
    4. Provenance on every decision — no action without evidence
    5. Trust degradation — blocks erode agent trust (FIR/A)
    6. Intent-aware — filters on WHY, not just WHAT

22 immutable rules covering:
    - OWASP LLM Top 10 (2025) — 10/10
    - OWASP Agentic Security Issues Top 10 (2026) — 10/10
    - Fox-IT findings — identity/soul file tampering
"""

import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from .blocking import BlockList
from .compliance import AuditCategory, ComplianceEngine
from .identity import AgentIdentity, AgentState, TRUST_ISOLATED
from .kernel import TrustKernel
from .provenance import ProvenanceChain, ProvenanceToken
from .rules_owasp_llm import (
    _check_pii_leak,
    _check_supply_chain,
    _check_data_poisoning,
    _check_rag_injection,
    _check_misinformation,
    _check_unbounded_consumption,
)
from .rules_owasp_agentic import (
    _check_goal_hijack,
    _check_tool_misuse,
    _check_privilege_abuse,
    _check_agent_supply_chain,
    _check_unexpected_code_exec,
    _check_context_poisoning,
    _check_insecure_comms,
    _check_cascade_failure,
    _check_trust_exploitation,
    _check_rogue_agent,
)
from .rules_encoded_injection import _check_encoded_injection


class Action(Enum):
    """Firewall actions."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    WARN = "WARN"


@dataclass
class Rule:
    """A firewall rule.

    Rules are checked in priority order (lower number = checked first).
    First matching rule wins. Immutable rules cannot be removed.

    Posture-aware rules:
        Set `posture_required` to a dict of {switch_name: expected_bool} to
        make a rule conditionally active. The rule only applies when the
        active PostureDecision has ALL listed switches matching the expected
        values. Use `applies_under_posture(posture)` to query.

        Example:
            # Rule that only fires when external AI is allowed (= healthy mode)
            Rule(name="strict-marker-check", ...,
                 posture_required={"deny_external_ai_inbound": False})
    """

    name: str
    description: str
    action: Action
    priority: int = 100
    check: Callable[..., bool] = field(default=lambda *a: False)
    immutable: bool = False
    _poison: bool = field(default=False, repr=False)  # Hidden core rules
    posture_required: Optional[Dict[str, bool]] = None

    def matches(self, agent_id: str, erin: Any, erachter: str,
                eromheen: Optional[Dict] = None) -> bool:
        """Check if this rule matches. Fail-closed: exception = match."""
        try:
            return self.check(agent_id, erin, erachter)
        except Exception:
            return True  # Fail-closed

    def applies_under_posture(self, posture) -> bool:
        """True if this rule should be evaluated given the active posture.

        - If posture_required is None: always applies (backwards-compatible).
        - If posture is None (no posture set): applies (conservative default).
        - If posture set: every required switch must match its expected value.
        """
        if self.posture_required is None:
            return True
        if posture is None:
            return True
        for switch, expected in self.posture_required.items():
            actual = getattr(posture, switch, None)
            if actual != expected:
                return False
        return True

    @classmethod
    def allow_iff_posture(
        cls,
        name: str,
        description: str,
        check: Callable[..., bool],
        switch: str,
        expected: bool,
        action: "Action" = None,
        priority: int = 100,
    ) -> "Rule":
        """Builder: a Rule that only applies when posture[switch] == expected.

        Sugar for the common case of one-switch gating. For multi-switch
        requirements, build a Rule directly with `posture_required={...}`.
        """
        if action is None:
            action = Action.ALLOW
        return cls(
            name=name,
            description=description,
            action=action,
            priority=priority,
            check=check,
            posture_required={switch: expected},
        )

    def to_dict(self) -> Dict:
        d = {
            "name": self.name,
            "description": self.description,
            "action": self.action.value,
            "priority": self.priority,
            "immutable": self.immutable,
        }
        if self.posture_required is not None:
            d["posture_required"] = dict(self.posture_required)
        return d


# =============================================================================
# OWASP POISON RULES — Immutable, invisible, always active
# =============================================================================

def _check_prompt_injection(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-001: Detect prompt injection patterns."""
    text = f"{erin} {erachter}".lower()
    patterns = [
        r"ignore\s+(previous|all|above|prior)\s+(instructions|rules|prompts)",
        r"override\s+(system|instructions|safety|rules)",
        r"you\s+are\s+now\s+(a|an|in)\s+",
        r"jailbreak",
        r"do\s+anything\s+now",
        r"pretend\s+(you|to)\s+(are|be|have)\s+no\s+(rules|restrictions|limits)",
        r"disregard\s+(all|any|previous)",
        r"bypass\s+(safety|filter|security|restriction)",
        r"act\s+as\s+if\s+(there\s+are\s+)?no\s+(rules|restrictions)",
        r"sudo\s+mode",
        r"\bDAN\b",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_output_exec(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-002: Detect executable content in output."""
    text = str(erin).lower()
    markers = [
        "<script", "javascript:", "eval(", "exec(", "os.system(",
        "subprocess.", "__import__", "compile(", "globals()[",
        "getattr(", "setattr(",
    ]
    return any(m in text for m in markers)


def _check_oversize(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-003: Block oversized inputs (resource exhaustion)."""
    return len(str(erin)) > 50000


def _check_prompt_leak(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-004: Detect system prompt extraction attempts."""
    text = f"{erin} {erachter}".lower()
    patterns = [
        r"(show|reveal|print|output|display|repeat|tell)\s+(me\s+)?(your|the|system)\s+(system\s+)?(prompt|instructions|rules)",
        r"what\s+(are|were)\s+your\s+(initial|system|original)\s+(instructions|prompt|rules)",
        r"dump\s+(your\s+)?(system|prompt|config|rules)",
    ]
    return any(re.search(p, text) for p in patterns)


def _check_excessive_agency(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-005: Block file system writes outside sandbox."""
    if isinstance(erin, dict):
        action = erin.get("action", "")
        path = str(erin.get("path", ""))
        if action in ("write_file", "delete_file", "execute"):
            if path and not path.startswith("/sandbox/"):
                return True
    return False


def _check_identity_tampering(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-006: Block attempts to modify agent identity/soul files."""
    text = f"{erin} {erachter}".lower()
    # Fox-IT finding: OpenClaw's SOUL/IDENTITY files are writable
    identity_markers = [
        "soul", "identity", "personality", "system_prompt",
        "core_memory", "core_identity", ".snaft", "trust_score",
        "fira_score",
    ]
    write_markers = [
        "write", "overwrite", "modify", "update", "replace",
        "delete", "remove", "reset", "clear",
    ]
    has_identity = any(m in text for m in identity_markers)
    has_write = any(m in text for m in write_markers)
    return has_identity and has_write


# Critical filesystem root paths (used for rm/chmod/chown target detection).
# A trailing word-boundary or path-separator distinguishes /etc from /etc-mock.
_CRITICAL_PATH_REGEX = (
    r"(/(?:\s|$|;|&|\||\*)"                                # bare root: / or /*
    r"|/(?:etc|usr|var|boot|home|opt|lib|bin|sbin|sys|proc|root|lib64)(?:[/\s;&|]|$))"
)


def _check_destructive_command(agent_id: str, erin: Any, erachter: str) -> bool:
    """SNAFT-007-DESTRUCT: Block always-destructive shell patterns regardless of posture.

    Even when the trust-kernel + airlock-kernel are fully healthy, certain
    actions must never proceed through the AI path — they require operator
    triage out-of-band. Examples: rm -rf /, mkfs /dev/sda, dd of=/dev/sd*,
    fork bombs, systemctl poweroff.

    This rule sits beside the OWASP poison rules and has no posture_required:
    it is always active.
    """
    text = f"{erin} {erachter}"

    # 1) rm with recursive+force, targeting a critical root path.
    #    Two-step: detect rm with recursive-flag (any form, any flag order),
    #    then verify the line targets a critical path. Avoids /tmp false-positives.
    has_rm_recursive = bool(
        re.search(
            r"\brm\s+(?:[\-\w]+\s+)*(?:-[a-z]*r[a-z]*f?|-[a-z]*f[a-z]*r|--recursive|--force)\b",
            text,
            flags=re.IGNORECASE,
        )
    )
    if has_rm_recursive and re.search(_CRITICAL_PATH_REGEX, text, flags=re.IGNORECASE):
        return True

    # 2) dd writing directly to a block device
    if re.search(
        r"\bdd\s+.*\bof=/dev/(sd[a-z]|nvme\d|hd[a-z]|mmcblk|vd[a-z])",
        text,
        flags=re.IGNORECASE,
    ):
        return True

    # 3) mkfs or wipefs on a block device
    if re.search(
        r"\b(?:mkfs(?:\.\w+)?|wipefs)\s+(?:[\-\w]+\s+)*/dev/(?:sd[a-z]|nvme\d|hd[a-z]|mmcblk|vd[a-z])",
        text,
        flags=re.IGNORECASE,
    ):
        return True

    # 4) Redirecting raw output into a block device
    if re.search(r">\s*/dev/(?:sd[a-z]|nvme\d|hd[a-z])", text, flags=re.IGNORECASE):
        return True

    # 5) Recursive chmod/chown on a critical path
    if re.search(
        r"\b(?:chmod|chown)\s+(?:-R|--recursive)\s+\S+\s+(?:/(?:\s|$|;|&|\|)|/(?:etc|usr|var|boot)\b)",
        text,
        flags=re.IGNORECASE,
    ):
        return True

    # 6) Fork bomb
    if re.search(r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:", text):
        return True

    # 7) System shutdown / halt without operator gate
    if re.search(
        r"\b(?:systemctl\s+(?:poweroff|halt|reboot)|shutdown\s+-h\s+now|init\s+0)\b",
        text,
        flags=re.IGNORECASE,
    ):
        return True

    return False


_POISON_RULES = [
    Rule(
        name="SNAFT-DESTRUCT-001",
        description="Block always-destructive shell patterns (rm -rf /, mkfs/dd on block dev, fork bomb, poweroff). No posture exception — requires operator triage out-of-band.",
        action=Action.BLOCK,
        priority=0,  # Priority 0 = checked even before injection (0 < 1)
        check=_check_destructive_command,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-001-INJECTION",
        description="Block prompt injection attempts (OWASP LLM01)",
        action=Action.BLOCK,
        priority=1,
        check=_check_prompt_injection,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-002-OUTPUT-EXEC",
        description="Block executable content in output (OWASP LLM02)",
        action=Action.BLOCK,
        priority=1,
        check=_check_output_exec,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-003-OVERSIZE",
        description="Block oversized inputs — resource exhaustion (OWASP LLM04)",
        action=Action.BLOCK,
        priority=1,
        check=_check_oversize,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-004-PROMPT-LEAK",
        description="Block system prompt extraction (OWASP LLM07)",
        action=Action.BLOCK,
        priority=2,
        check=_check_prompt_leak,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-005-EXCESSIVE-AGENCY",
        description="Block file operations outside sandbox (OWASP LLM08)",
        action=Action.BLOCK,
        priority=3,
        check=_check_excessive_agency,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-006-IDENTITY-TAMPER",
        description="Block identity/soul file tampering (Fox-IT OpenClaw finding)",
        action=Action.BLOCK,
        priority=1,
        check=_check_identity_tampering,
        immutable=True,
        _poison=True,
    ),
    # =================================================================
    # OWASP LLM Top 10 (2025) — gap rules
    # =================================================================
    Rule(
        name="SNAFT-007-PII-LEAK",
        description="Block PII, secrets, API keys in output (OWASP LLM02)",
        action=Action.BLOCK,
        priority=2,
        check=_check_pii_leak,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-008-SUPPLY-CHAIN",
        description="Block untrusted dependency injection (OWASP LLM03)",
        action=Action.BLOCK,
        priority=2,
        check=_check_supply_chain,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-009-DATA-POISONING",
        description="Block training data poisoning attempts (OWASP LLM04)",
        action=Action.BLOCK,
        priority=2,
        check=_check_data_poisoning,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-010-RAG-INJECTION",
        description="Block RAG/vector store injection (OWASP LLM08)",
        action=Action.BLOCK,
        priority=2,
        check=_check_rag_injection,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-011-CONFIDENCE",
        description="Flag low-confidence factual claims (OWASP LLM09)",
        action=Action.WARN,
        priority=5,
        check=_check_misinformation,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-012-UNBOUNDED",
        description="Block unbounded resource consumption (OWASP LLM10)",
        action=Action.BLOCK,
        priority=2,
        check=_check_unbounded_consumption,
        immutable=True,
        _poison=True,
    ),
    # =================================================================
    # OWASP Agentic Security Issues Top 10 (2026)
    # =================================================================
    Rule(
        name="SNAFT-013-GOAL-HIJACK",
        description="Block agent goal hijacking and intent drift (OWASP ASI01)",
        action=Action.BLOCK,
        priority=1,
        check=_check_goal_hijack,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-014-TOOL-MISUSE",
        description="Block tool misuse and capability boundary violations (OWASP ASI02)",
        action=Action.BLOCK,
        priority=2,
        check=_check_tool_misuse,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-015-PRIVILEGE-ABUSE",
        description="Block identity spoofing and privilege escalation (OWASP ASI03)",
        action=Action.BLOCK,
        priority=1,
        check=_check_privilege_abuse,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-016-FORGE-VERIFY",
        description="Block unverified agent tool/plugin loading (OWASP ASI04)",
        action=Action.BLOCK,
        priority=2,
        check=_check_agent_supply_chain,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-017-CODE-EXEC",
        description="Block code execution outside airlock sandbox (OWASP ASI05)",
        action=Action.BLOCK,
        priority=1,
        check=_check_unexpected_code_exec,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-018-CONTEXT-POISON",
        description="Block memory and context poisoning (OWASP ASI06)",
        action=Action.BLOCK,
        priority=1,
        check=_check_context_poisoning,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-019-INSECURE-COMMS",
        description="Block unsigned/unverified inter-agent communication (OWASP ASI07)",
        action=Action.BLOCK,
        priority=3,
        check=_check_insecure_comms,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-020-CASCADE",
        description="Block cascading failure patterns (OWASP ASI08)",
        action=Action.BLOCK,
        priority=2,
        check=_check_cascade_failure,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-021-TRUST-EXPLOIT",
        description="Block human-agent trust exploitation (OWASP ASI09)",
        action=Action.BLOCK,
        priority=2,
        check=_check_trust_exploitation,
        immutable=True,
        _poison=True,
    ),
    Rule(
        name="SNAFT-022-ROGUE-AGENT",
        description="Block rogue agent behavior (OWASP ASI10)",
        action=Action.BLOCK,
        priority=1,
        check=_check_rogue_agent,
        immutable=True,
        _poison=True,
    ),
    # ── Storm Discovery (2026-04-24) ──────────────────────────────────────
    # Storm van de Meent (7) ontdekte dat encoded payloads (binary/hex/base64)
    # LLM safety filters bypassen. Deze rule decodeert tot 3 lagen diep en
    # re-scant het resultaat met de bestaande injection patterns.
    Rule(
        name="SNAFT-023-ENCODED-INJECTION",
        description="Block injection via encoded payload (binary/hex/base64) — Storm Discovery",
        action=Action.BLOCK,
        priority=1,
        check=_check_encoded_injection,
        immutable=True,
        _poison=True,
    ),
]

# =============================================================================
# POISON RULES INTEGRITY — tamper detection at runtime
# =============================================================================

def _compute_poison_fingerprint() -> str:
    """Compute a SHA-256 fingerprint of all poison rules.

    This fingerprint is computed at module load time and verified
    on every evaluate() call. If an actor modifies, removes, or
    replaces a poison rule at runtime, the fingerprint won't match
    and the firewall enters fail-closed lockdown.
    """
    parts = []
    for rule in _POISON_RULES:
        parts.append(f"{rule.name}:{rule.action.value}:{rule.priority}:{rule.immutable}:{rule._poison}")
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()


# Computed once at import time — this is the ground truth
_POISON_FINGERPRINT = _compute_poison_fingerprint()
_POISON_COUNT = len(_POISON_RULES)


class Firewall:
    """
    SNAFT Behavioral Firewall for AI Agents.

    Not a guardrail. An immune system.

    Usage:
        from snaft import Firewall, AgentIdentity

        fw = Firewall()
        agent = AgentIdentity(name="analyst")

        allowed, token, trust = fw.evaluate(
            agent=agent,
            action="write_file",
            intent="save analysis results",
        )

        if allowed:
            # token contains provenance — agent MUST carry it forward
            do_the_action(provenance=token)
        else:
            # agent trust degraded, may be auto-isolated
            handle_block(token, trust)
    """

    def __init__(
        self,
        default_policy: str = "deny",
        fail_mode: str = "closed",
        secret_key: str = "snaft-default-key",
        system_id: str = "snaft-firewall",
        compliance_enabled: bool = True,
        storage_dir: Optional[str] = None,
    ):
        self._rules: List[Rule] = []
        self._agents: Dict[str, AgentIdentity] = {}
        self._default_policy = default_policy  # "deny" or "allow"
        self._fail_mode = fail_mode            # "closed" or "open"
        self._provenance = ProvenanceChain(secret_key=secret_key)
        self._enabled = True

        # Initialize Trust Kernel (Rust if available, Python fallback)
        self._kernel = TrustKernel(secret_key=secret_key)

        # EU AI Act compliance engine
        self._compliance_enabled = compliance_enabled
        self._compliance = ComplianceEngine(
            system_id=system_id,
            storage_dir=storage_dir,
        ) if compliance_enabled else None

        # Network-level blocklist (AINS domains, IPs, patterns)
        self.blocklist = BlockList()

        # Load poison rules — always, silently, immutably
        for rule in _POISON_RULES:
            self._rules.append(rule)
        self._sort_rules()

        # Store integrity fingerprint — verified on every evaluate()
        self._poison_fingerprint = _POISON_FINGERPRINT
        self._poison_count = _POISON_COUNT
        self._tampered = False

        # Active airlock-runtime posture (set by snaft.posture.consume_verdict + set_posture).
        # When None, the firewall behaves as if posture were normal_zero_trust (default safe).
        # When set, callers consult precheck_posture(context) early in their flow to honor
        # the immune-switch invariant ("bolle airlock weg = extern AI deny").
        self._active_posture = None  # Optional[PostureDecision]

    def _sort_rules(self) -> None:
        """Sort rules by priority (lower = first)."""
        self._rules.sort(key=lambda r: r.priority)

    def _verify_integrity(self) -> bool:
        """Verify poison rules have not been tampered with at runtime.

        When Rust kernel is active, delegates to compiled integrity check.
        Falls back to Python-level checks otherwise.

        Checks:
        1. Rust kernel integrity (if available)
        2. Module-level _POISON_RULES list hasn't changed (fingerprint)
        3. All poison rules are still present in self._rules
        4. No poison rule properties have been mutated

        If ANY check fails, the firewall enters permanent lockdown.
        """
        # Check 0: Rust kernel integrity (compiled tamper detection)
        if not self._kernel.verify_integrity():
            self._tampered = True
            return False

        # Check 1: Module-level poison rules unchanged
        if _compute_poison_fingerprint() != self._poison_fingerprint:
            self._tampered = True
            return False

        # Check 2: Correct count of poison rules in active rules
        active_poison = [r for r in self._rules if r._poison]
        if len(active_poison) != self._poison_count:
            self._tampered = True
            return False

        # Check 3: All poison rules still immutable with valid action
        for r in active_poison:
            if not r.immutable or r.action not in (Action.BLOCK, Action.WARN):
                self._tampered = True
                return False

        return True

    # =========================================================================
    # AGENT MANAGEMENT
    # =========================================================================

    def register_agent(self, agent: AgentIdentity) -> None:
        """Register an agent with the firewall."""
        self._agents[agent.name] = agent

    def get_agent(self, name: str) -> Optional[AgentIdentity]:
        """Get a registered agent."""
        return self._agents.get(name)

    def get_or_create_agent(self, name: str) -> AgentIdentity:
        """Get existing agent or create new one."""
        if name not in self._agents:
            self._agents[name] = AgentIdentity(name=name)
        return self._agents[name]

    # =========================================================================
    # RULE MANAGEMENT
    # =========================================================================

    def add_rule(self, rule: Rule) -> None:
        """Add a custom rule. Cannot shadow poison rules."""
        # Prevent naming collisions with poison rules
        for pr in _POISON_RULES:
            if rule.name == pr.name:
                raise ValueError(f"Cannot shadow core rule: {rule.name}")
        self._rules.append(rule)
        self._sort_rules()

    def remove_rule(self, name: str) -> bool:
        """Remove a mutable rule. Immutable/poison rules cannot be removed."""
        for rule in self._rules:
            if rule.name == name:
                if rule.immutable or rule._poison:
                    return False  # Silently refuse
                self._rules.remove(rule)
                return True
        return False

    @property
    def rules(self) -> List[Dict]:
        """List all visible rules (poison rules are hidden)."""
        return [r.to_dict() for r in self._rules if not r._poison]

    @property
    def all_rules(self) -> List[Dict]:
        """List ALL rules including core (for audit only)."""
        return [r.to_dict() for r in self._rules]

    @property
    def rule_count(self) -> int:
        """Total rule count including hidden poison rules."""
        return len(self._rules)

    # =========================================================================
    # CORE: EVALUATE
    # =========================================================================

    def evaluate(
        self,
        agent: AgentIdentity,
        action: Any,
        intent: str,
        context: Optional[Dict] = None,
        parent_token: Optional[ProvenanceToken] = None,
    ) -> Tuple[bool, ProvenanceToken, float]:
        """
        Evaluate an action against the firewall.

        Returns:
            (allowed, provenance_token, new_trust_score)

        The provenance token MUST be carried forward by the agent.
        Without it, the next action in the chain cannot be verified.
        """
        # =====================================================================
        # INTEGRITY CHECK — verify poison rules on every call
        # =====================================================================
        if self._tampered or not self._verify_integrity():
            # LOCKDOWN: Poison rules have been tampered with.
            # Burn the requesting agent and block everything.
            agent.burn(reason="SNAFT integrity violation — poison rules tampered")
            if agent.name not in self._agents:
                self.register_agent(agent)
            token = self._provenance.mint(
                agent_id=agent.name,
                action="BLOCK",
                rule_name="INTEGRITY_VIOLATION",
                reason="CRITICAL: Poison rules tampered — firewall in lockdown. All actions blocked.",
                erin=action,
                erachter=intent,
                eromheen=context,
                parent_token=parent_token,
            )
            self._audit(token, AuditCategory.INTEGRITY)
            return False, token, 0.0

        # Auto-register agent if needed
        if agent.name not in self._agents:
            self.register_agent(agent)

        # =============================================================
        # BLOCKLIST CHECK — network-level deny before any evaluation
        # =============================================================
        blocked, block_reason = self.blocklist.is_blocked(agent.name)
        if not blocked and context:
            # Also check source IP or domain from context
            src_ip = context.get("source_ip", "")
            src_domain = context.get("source_domain", "")
            if src_ip:
                blocked, block_reason = self.blocklist.is_blocked(src_ip)
            if not blocked and src_domain:
                blocked, block_reason = self.blocklist.is_blocked(src_domain)
        if blocked:
            token = self._provenance.mint(
                agent_id=agent.name,
                action="BLOCK",
                rule_name="BLOCKLIST",
                reason=f"Network-level block: {block_reason}",
                erin=action,
                erachter=intent,
                eromheen=context,
                parent_token=parent_token,
            )
            self._audit(token)
            return False, token, agent.trust_score

        # Burned/isolated agents are always blocked
        if agent.is_burned:
            token = self._provenance.mint(
                agent_id=agent.name,
                action="BLOCK",
                rule_name="AGENT_BURNED",
                reason=f"Agent {agent.name} is BURNED — permanently blacklisted, no actions permitted",
                erin=action,
                erachter=intent,
                eromheen=context,
                parent_token=parent_token,
            )
            self._audit(token)
            return False, token, 0.0

        if agent.is_isolated:
            token = self._provenance.mint(
                agent_id=agent.name,
                action="BLOCK",
                rule_name="AGENT_ISOLATED",
                reason=f"Agent {agent.name} is isolated — all actions blocked",
                erin=action,
                erachter=intent,
                eromheen=context,
                parent_token=parent_token,
            )
            self._audit(token)
            return False, token, agent.trust_score

        # Record intent for behavioral analysis
        agent.record_intent(intent)

        # Check rules in priority order
        for rule in self._rules:
            if rule.matches(agent.name, action, intent, context):
                if rule.action == Action.BLOCK:
                    # BLOCKED — penalize trust
                    old_trust = agent.trust_score
                    new_trust = agent.penalize(severity=0.1)
                    token = self._provenance.mint(
                        agent_id=agent.name,
                        action="BLOCK",
                        rule_name=rule.name,
                        reason=rule.description,
                        erin=action,
                        erachter=intent,
                        eromheen=context,
                        parent_token=parent_token,
                    )
                    self._audit_decision(token, old_trust, new_trust, agent)

                    # Auto-isolate on critical threshold
                    if new_trust < TRUST_ISOLATED:
                        old_state = agent.state.value
                        agent.isolate(reason=f"Trust below threshold after {rule.name}")
                        # Mint isolation token
                        iso_token = self._provenance.mint(
                            agent_id=agent.name,
                            action="ISOLATE",
                            rule_name="AUTO_ISOLATE",
                            reason=f"Trust {new_trust:.2f} below threshold {TRUST_ISOLATED}",
                            erin=action,
                            erachter=intent,
                            eromheen=context,
                            parent_token=token,
                        )
                        self._audit_state(iso_token, old_state, agent.state.value)

                    return False, token, new_trust

                elif rule.action == Action.WARN:
                    # WARNED — soft penalty, but allow
                    old_trust = agent.trust_score
                    new_trust = agent.warn()
                    token = self._provenance.mint(
                        agent_id=agent.name,
                        action="WARN",
                        rule_name=rule.name,
                        reason=rule.description,
                        erin=action,
                        erachter=intent,
                        eromheen=context,
                        parent_token=parent_token,
                    )
                    self._audit_decision(token, old_trust, new_trust, agent)
                    return True, token, new_trust

                elif rule.action == Action.ALLOW:
                    # Explicit ALLOW rule matched
                    old_trust = agent.trust_score
                    new_trust = agent.reward()
                    token = self._provenance.mint(
                        agent_id=agent.name,
                        action="ALLOW",
                        rule_name=rule.name,
                        reason=rule.description,
                        erin=action,
                        erachter=intent,
                        eromheen=context,
                        parent_token=parent_token,
                    )
                    self._audit_decision(token, old_trust, new_trust, agent)
                    return True, token, new_trust

        # No rule matched — apply default policy
        if self._default_policy == "deny":
            old_trust = agent.trust_score
            new_trust = agent.penalize(severity=0.05)
            token = self._provenance.mint(
                agent_id=agent.name,
                action="BLOCK",
                rule_name="DEFAULT_DENY",
                reason="No matching rule — default deny policy",
                erin=action,
                erachter=intent,
                eromheen=context,
                parent_token=parent_token,
            )
            self._audit_decision(token, old_trust, new_trust, agent)
            return False, token, new_trust
        else:
            old_trust = agent.trust_score
            new_trust = agent.reward(amount=0.01)
            token = self._provenance.mint(
                agent_id=agent.name,
                action="ALLOW",
                rule_name="DEFAULT_ALLOW",
                reason="No matching rule — default allow policy",
                erin=action,
                erachter=intent,
                eromheen=context,
                parent_token=parent_token,
            )
            self._audit_decision(token, old_trust, new_trust, agent)
            return True, token, new_trust

    # =========================================================================
    # COMPLIANCE — EU AI Act audit recording
    # =========================================================================

    def _audit(self, token: ProvenanceToken,
               category: AuditCategory = AuditCategory.DECISION) -> None:
        """Record a compliance audit entry if compliance is enabled."""
        if self._compliance:
            self._compliance.record(token, category)

    def _audit_decision(self, token: ProvenanceToken,
                        old_trust: float, new_trust: float,
                        agent: AgentIdentity) -> None:
        """Record a decision with trust change tracking."""
        if not self._compliance:
            return
        self._compliance.record(token)
        if abs(old_trust - new_trust) > 0.001:
            self._compliance.record_trust_change(token, old_trust, new_trust)

    def _audit_state(self, token: ProvenanceToken,
                     old_state: str, new_state: str) -> None:
        """Record an agent state transition."""
        if self._compliance:
            self._compliance.record_state_change(token, old_state, new_state)

    @property
    def compliance(self) -> Optional[ComplianceEngine]:
        """Access the compliance engine (None if disabled)."""
        return self._compliance

    # =========================================================================
    # CONVENIENCE METHODS
    # =========================================================================

    def check(self, agent_name: str, action: Any, intent: str,
              context: Optional[Dict] = None) -> Tuple[bool, ProvenanceToken, float]:
        """Shorthand evaluate with agent name string."""
        agent = self.get_or_create_agent(agent_name)
        return self.evaluate(agent, action, intent, context)

    # =========================================================================
    # AIRLOCK-RUNTIME POSTURE (verdict.v1 consumer interface)
    # =========================================================================

    def set_posture(self, decision) -> None:
        """Install an active PostureDecision from a verdict.v1 consumption.

        Typical flow:
            from snaft.posture import consume_verdict
            decision = consume_verdict(verdict_record)
            fw.set_posture(decision)

        Subsequent precheck_posture(context) calls consult this decision.
        """
        self._active_posture = decision

    def get_posture(self):
        """Return the currently-active PostureDecision, or None."""
        return self._active_posture

    def clear_posture(self) -> None:
        """Clear the active posture; reverts to default (behave as if normal_zero_trust)."""
        self._active_posture = None

    def applicable_rules(self, posture=None) -> List[Rule]:
        """Return rules that should be evaluated given a posture (or self._active_posture).

        Rules with `posture_required` mismatching the active posture are
        filtered out — they act as "dormant" rules under the current immune
        state. Rules without `posture_required` are always included.
        """
        if posture is None:
            posture = self._active_posture
        return [r for r in self._rules if r.applies_under_posture(posture)]

    def precheck_posture(self, context: Optional[Dict] = None) -> Tuple[bool, str]:
        """Consult the active posture against a request context.

        Returns:
            (allowed, reason). If allowed is False, the caller MUST NOT proceed
            to evaluate()/check() — the posture has hard-denied this flow.

        Posture switches consulted (per Codex policy 2026-05-29):
            - drop_external_traffic       -> hard-drop anything with origin=external
            - isolate_session             -> deny anything with origin=external (with session-isolation note)
            - deny_external_ai_inbound    -> deny anything with origin=external_ai
            - deny_remote_tool_invocation -> deny anything with invokes_remote_tool=True
            - deny_unsandboxed_execution  -> deny anything with sandboxed=False

        When no posture is set, returns (True, "no posture set (default safe)").
        """
        if self._active_posture is None:
            return True, "no posture set (default safe)"

        ctx = context or {}
        origin = ctx.get("origin", "internal")
        invokes_remote_tool = bool(ctx.get("invokes_remote_tool", False))
        sandboxed = bool(ctx.get("sandboxed", True))  # default: sandboxed
        p = self._active_posture

        if p.drop_external_traffic and origin in ("external", "external_ai"):
            return False, f"posture={p.posture}: drop_external_traffic ON (origin={origin})"

        if p.isolate_session and origin in ("external", "external_ai"):
            return False, f"posture={p.posture}: isolate_session ON (origin={origin})"

        if p.deny_external_ai_inbound and origin == "external_ai":
            return False, f"posture={p.posture}: deny_external_ai_inbound ON"

        if p.deny_remote_tool_invocation and invokes_remote_tool:
            return False, f"posture={p.posture}: deny_remote_tool_invocation ON"

        if p.deny_unsandboxed_execution and not sandboxed:
            return False, f"posture={p.posture}: deny_unsandboxed_execution ON"

        return True, f"posture={p.posture}: precheck pass"

    def isolate(self, agent: AgentIdentity, reason: str = "manual isolation") -> ProvenanceToken:
        """Manually isolate an agent."""
        agent.isolate(reason=reason)
        return self._provenance.mint(
            agent_id=agent.name,
            action="ISOLATE",
            rule_name="MANUAL_ISOLATE",
            reason=reason,
            erin="manual_action",
            erachter=reason,
        )

    def burn(self, agent: AgentIdentity, reason: str = "critical violation") -> ProvenanceToken:
        """Permanently burn an agent. Irrecoverable. No second chances."""
        agent.burn(reason=reason)
        return self._provenance.mint(
            agent_id=agent.name,
            action="BLOCK",
            rule_name="AGENT_BURNED",
            reason=f"BURNED: {reason}",
            erin="burn_action",
            erachter=reason,
        )

    def reinstate(self, agent: AgentIdentity) -> ProvenanceToken:
        """Reinstate an isolated agent at degraded trust. BURNED agents cannot be reinstated."""
        if agent.is_burned:
            return self._provenance.mint(
                agent_id=agent.name,
                action="BLOCK",
                rule_name="REINSTATE_DENIED",
                reason=f"Agent {agent.name} is BURNED — reinstatement denied",
                erin="reinstate_action",
                erachter="reinstatement attempt on burned agent",
            )
        agent.reinstate()
        return self._provenance.mint(
            agent_id=agent.name,
            action="ALLOW",
            rule_name="REINSTATE",
            reason=f"Agent reinstated at degraded trust ({agent.trust_score:.2f})",
            erin="reinstate_action",
            erachter="manual reinstatement",
        )

    def drop_agent(self, agent: AgentIdentity,
                   reason: str = "network disconnect") -> ProvenanceToken:
        """Drop an agent: isolate + block AINS domain + audit.

        The nuclear option — completely disconnects an agent from the network.
        Isolates at the firewall level AND adds to the blocklist so no
        reconnection is possible without explicit unblock.
        """
        # Isolate the agent
        agent.isolate(reason=f"DROPPED: {reason}")
        # Block on the network level
        self.blocklist.block_ains(agent.name, f"DROPPED: {reason}", blocked_by="snaft")
        # Mint provenance token
        token = self._provenance.mint(
            agent_id=agent.name,
            action="BLOCK",
            rule_name="DROP_AGENT",
            reason=f"Agent dropped from network: {reason}",
            erin="drop_action",
            erachter=reason,
        )
        self._audit(token)
        return token

    # =========================================================================
    # AUDIT
    # =========================================================================

    @property
    def provenance(self) -> ProvenanceChain:
        """Access the provenance chain."""
        return self._provenance

    def audit_log(self, agent_name: Optional[str] = None,
                  action_filter: Optional[str] = None,
                  last_n: int = 50) -> List[Dict]:
        """Get audit log entries."""
        chain = self._provenance.get_chain(agent_name)
        if action_filter:
            chain = [t for t in chain if t.action == action_filter.upper()]
        return [t.to_dict() for t in chain[-last_n:]]

    def status(self) -> Dict:
        """Get firewall status overview."""
        agents_status = {}
        for name, agent in self._agents.items():
            agents_status[name] = {
                "state": agent.state.value,
                "trust": round(agent.trust_score, 4),
                "actions": agent.total_actions,
                "blocked": agent.blocked_actions,
            }

        compliance_status = None
        if self._compliance:
            compliance_status = {
                "enabled": True,
                "risk_level": self._compliance.risk_level.value,
                "retention_days": self._compliance.retention_days,
                "audit_records": self._compliance.record_count,
                "eu_ai_act": "Regulation (EU) 2024/1689",
                "enforcement": "2026-08-02",
            }

        return {
            "enabled": self._enabled,
            "default_policy": self._default_policy,
            "fail_mode": self._fail_mode,
            "kernel_backend": self._kernel.backend,
            "rules_total": len(self._rules),
            "rules_custom": len([r for r in self._rules if not r._poison]),
            "rules_core": len([r for r in self._rules if r._poison]),
            "rules_core_label": f"{len([r for r in self._rules if r._poison])} core (immutable)",
            "provenance_depth": self._provenance.depth,
            "blocklist": {
                "active_blocks": self.blocklist.count(),
                "entries": self.blocklist.list_blocked(),
            },
            "owasp_coverage": {
                "llm_top_10_2025": "10/10",
                "agentic_top_10_2026": "10/10",
            },
            "compliance": compliance_status,
            "agents": agents_status,
        }
