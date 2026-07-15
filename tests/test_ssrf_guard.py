"""
Tests for backend/ssrf_guard.py — the bounded+TTL DNS cache and the
private/reserved-IP blocking logic that egress_proxy.py and
phishing_sandbox_scan.py both build on.

PATCH NOTES (post-audit-review fix):
  - L8/L9: test_dns_cache_hit_within_ttl_does_not_re_resolve previously
    defined an unused `counting_getaddrinfo` helper and an unused
    `real_run_in_executor` variable -- neither was ever called; the
    test actually exercises `fake_run_in_executor` via the monkeypatch
    below. Removed both as dead code with no functional change to what
    the test verifies.
"""

import asyncio

import pytest

from backend import ssrf_guard as sg


def test_is_blocked_ip_covers_the_obvious_ranges():
    assert sg._is_blocked_ip("127.0.0.1") is True          # loopback
    assert sg._is_blocked_ip("10.0.0.5") is True            # RFC1918 private
    assert sg._is_blocked_ip("192.168.1.1") is True         # RFC1918 private
    assert sg._is_blocked_ip("169.254.169.254") is True     # cloud metadata (link-local)
    assert sg._is_blocked_ip("224.0.0.1") is True           # multicast
    assert sg._is_blocked_ip("not-an-ip") is True           # unparseable -> fail closed
    assert sg._is_blocked_ip("8.8.8.8") is False            # real public IP
    assert sg._is_blocked_ip("140.82.112.3") is False       # a real github.com IP


@pytest.mark.integration
async def test_is_target_allowed_real_domains():
    assert await sg.is_target_allowed("https://github.com") is True
    assert await sg.is_target_allowed("http://127.0.0.1:8000/admin") is False
    assert await sg.is_target_allowed("http://localhost/") is False
    assert await sg.is_target_allowed("http://169.254.169.254/latest/meta-data/") is False


@pytest.mark.integration
async def test_resolve_validated_ip():
    ip = await sg.resolve_validated_ip("github.com")
    assert ip is not None
    assert sg._is_blocked_ip(ip) is False

    assert await sg.resolve_validated_ip("127.0.0.1") is None
    assert await sg.resolve_validated_ip("169.254.169.254") is None


async def test_dns_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(sg, "_DNS_CACHE_MAX_ENTRIES", 5)
    sg._dns_cache.clear()

    for i in range(8):
        await sg._resolve_all_ips(f"host{i}.invalid.test")

    assert len(sg._dns_cache) <= 5, "cache must not grow past its configured cap"


async def test_dns_cache_entries_expire(monkeypatch):
    monkeypatch.setattr(sg, "_DNS_CACHE_TTL_SECONDS", 0.2)
    monkeypatch.setattr(sg, "_DNS_FAILURE_TTL_SECONDS", 0.2)
    sg._dns_cache.clear()

    await sg._resolve_all_ips("expiry-test.invalid")
    first_expiry = sg._dns_cache["expiry-test.invalid"][1]

    await asyncio.sleep(0.3)
    await sg._resolve_all_ips("expiry-test.invalid")  # must re-resolve, not reuse the stale entry
    second_expiry = sg._dns_cache["expiry-test.invalid"][1]

    assert second_expiry > first_expiry, "an expired entry must be refreshed, not reused"


async def test_dns_cache_hit_within_ttl_does_not_re_resolve(monkeypatch):
    """
    A cache HIT shouldn't trigger a fresh getaddrinfo() call -- this is
    the inverse of the expiry test above, confirming the cache actually
    short-circuits resolution rather than just bookkeeping silently.
    """
    sg._dns_cache.clear()
    call_count = {"n": 0}

    async def fake_run_in_executor(executor, func, *args):
        call_count["n"] += 1
        return [(None, None, None, None, ("93.184.216.34", 0))]

    monkeypatch.setattr(asyncio.get_event_loop(), "run_in_executor", fake_run_in_executor)

    await sg._resolve_all_ips("cache-hit-test.invalid")
    await sg._resolve_all_ips("cache-hit-test.invalid")
    await sg._resolve_all_ips("cache-hit-test.invalid")

    assert call_count["n"] == 1, "repeated lookups within the TTL window must hit the cache, not re-resolve"


async def test_failed_resolution_uses_short_failure_ttl_not_full_ttl(monkeypatch):
    """
    Regression test for M3: a failed resolution (ips == []) used to be
    cached for the full 5-minute TTL, meaning one transient DNS blip
    could keep a legitimate target blocked for 5 minutes. A failed
    lookup should expire much sooner than a successful one.
    """
    sg._dns_cache.clear()

    async def failing_run_in_executor(executor, func, *args):
        raise OSError("simulated DNS failure")

    monkeypatch.setattr(asyncio.get_event_loop(), "run_in_executor", failing_run_in_executor)
    await sg._resolve_all_ips("always-fails.invalid")

    ips, expiry = sg._dns_cache["always-fails.invalid"]
    assert ips == []
    remaining = expiry - __import__("time").monotonic()
    assert remaining <= sg._DNS_FAILURE_TTL_SECONDS, (
        "a failed resolution must use the short failure TTL, not the full success TTL"
    )
