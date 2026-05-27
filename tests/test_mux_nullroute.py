"""MUX-0x00 / NullRouteMux — null-route detection engine tests.

Demonstrates the SNAFT null-route ("gemuxed naar 0x00") decision engine:
abnormal traffic is detected per-IP via dual-threshold analysis (rate +
path-repetition + entropy), then the attacker is marked for null-routing
while their request metadata is absorbed for forensics.

The decision engine lives here (snaft.mux.NullRouteMux). The wire-tactic
(connection-hold vs HTTP-200-null-body) is the responsibility of the
adjacent ASGI/Express middleware that consumes these decisions.
"""
from snaft.mux import NullRouteMux


def test_path_repetition_triggers_null_route():
    """Same path hit repetition_threshold times -> null-route decision."""
    mux = NullRouteMux(repetition_threshold=3, rate_threshold=1000)
    ip = "203.0.113.7"
    path = "/api/ains/lookup"
    decisions = [mux.check(ip, path, "GET") for _ in range(3)]
    assert decisions[-1].should_null_route is True
    assert "repetition" in decisions[-1].reason.lower()
    assert decisions[-1].is_new_trigger is True  # first trigger fires flare once


def test_rate_threshold_triggers_null_route():
    """More than rate_threshold requests in window -> null-route decision."""
    mux = NullRouteMux(rate_threshold=5, window_seconds=60.0, repetition_threshold=1000)
    ip = "203.0.113.8"
    decisions = [mux.check(ip, f"/api/p{i}", "GET") for i in range(7)]
    assert any(d.should_null_route for d in decisions)
    triggered = next(d for d in decisions if d.should_null_route)
    assert "rate" in triggered.reason.lower()


def test_once_null_routed_stays_null_routed_and_absorbs():
    """After trigger, subsequent requests stay null-routed; metadata absorbed."""
    mux = NullRouteMux(repetition_threshold=2, rate_threshold=1000)
    ip = "203.0.113.9"
    path = "/api/lookup"
    for _ in range(2):
        mux.check(ip, path, "GET")  # trips on 2nd
    # subsequent check: stays null-routed, not a new trigger
    follow = mux.check(ip, path, "GET")
    assert follow.should_null_route is True
    assert follow.is_new_trigger is False
    # absorb attacker metadata — we learn, they get zero signal
    mux.absorb(ip, path, "POST", {"User-Agent": "sqlmap/1.7"}, b"' OR 1=1--")
    summary = mux.get_absorbed_summary(ip)
    assert summary["total_absorbed"] >= 1


def test_clean_traffic_passes():
    """Distinct low-rate paths never trigger null-route."""
    mux = NullRouteMux(rate_threshold=15, repetition_threshold=5)
    ip = "203.0.113.10"
    d = mux.check(ip, "/api/profile", "GET")
    assert d.should_null_route is False


def test_release_clears_null_route_flag():
    """Manual release clears the null-routed flag (un-routing, not amnesia:
    the path-history persists, so a still-fresh abnormal pattern can re-trigger)."""
    mux = NullRouteMux(repetition_threshold=2, rate_threshold=1000)
    ip = "203.0.113.11"
    for _ in range(2):
        mux.check(ip, "/x", "GET")
    assert mux.check(ip, "/x", "GET").should_null_route is True
    # release returns True when it actually un-routed an active offender
    assert mux.release(ip) is True
    # releasing an already-released / unknown IP returns False
    assert mux.release(ip) is False
