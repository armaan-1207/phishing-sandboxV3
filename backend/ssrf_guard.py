"""
Shared SSRF primitives: DNS resolution + private/reserved-IP blocking.

Used by:
  - phishing_sandbox_scan.py — the upfront check before navigating, and
    the per-request `context.route()` recheck (catches redirects/
    subresources the upfront check alone wouldn't see).
  - egress_proxy.py — the IP-pinning local proxy. A route-level recheck
    closes most of the gap but Python's check and Chromium's own later
    DNS resolution are still two separate lookups with a real (if tiny)
    time gap between them — that's the textbook DNS-rebinding TOCTOU.
    egress_proxy.py closes that gap completely by making the SAME
    resolution that gets validated the SAME one that gets connected to;
    see its module docstring.
"""

import asyncio
import ipaddress
import logging
import socket
import time
from urllib.parse import urlparse

logger = logging.getLogger("phishing_sandbox.ssrf_guard")

# Bounded AND TTL'd, not just bounded. Without an eviction policy, this
# dict grows forever across a long-lived process scanning many distinct
# domains (a real memory leak at scale). Without a TTL, a domain that
# resolved to a public IP once would be trusted for the rest of the
# container's life even if its DNS later starts pointing somewhere
# internal — caching the SSRF check makes the cache itself a staleness
# risk, not just a memory one.
_DNS_CACHE_MAX_ENTRIES = 2000
_DNS_CACHE_TTL_SECONDS = 300  # 5 minutes
_dns_cache = {}  # hostname -> (ips: list[str], expiry: float monotonic time)


async def _resolve_all_ips(hostname):
    now = time.monotonic()
    cached = _dns_cache.get(hostname)
    if cached and cached[1] > now:
        return cached[0]

    loop = asyncio.get_event_loop()
    try:
        infos = await loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
        ips = list({info[4][0] for info in infos})
    except Exception as e:
        logger.warning("DNS resolution failed for %s: %s", hostname, e, exc_info=True)
        ips = []

    if len(_dns_cache) >= _DNS_CACHE_MAX_ENTRIES:
        # dicts preserve insertion order in modern Python -- this evicts
        # the oldest entry rather than letting the cache grow unbounded.
        # Not true LRU (doesn't bump recently-used entries), but cheap
        # and sufficient to cap memory; swap for a real LRU structure if
        # you need eviction to favor hot domains specifically.
        _dns_cache.pop(next(iter(_dns_cache)))
    _dns_cache[hostname] = (ips, now + _DNS_CACHE_TTL_SECONDS)
    return ips


def _is_blocked_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable -> fail closed
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local or
        ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


async def is_target_allowed(url, allow_private_targets=False):
    """
    Resolve `url`'s hostname and reject if ANY resolved address is
    private/loopback/link-local/multicast/reserved/unspecified.

    KNOWN LIMITATION: this is a point-in-time check. It does not, by
    itself, defend against DNS rebinding (a DNS server returning a safe
    IP to this check and a different, internal IP moments later to
    Chromium's own separate resolution). The per-request
    `context.route()` recheck in phishing_sandbox_scan.py shrinks that
    window a lot; egress_proxy.py's IP-pinning closes it completely for
    traffic routed through it. Use both for the strongest guarantee.
    """
    if allow_private_targets:
        return True
    host = urlparse(url).hostname
    if not host:
        return False
    if host.lower() == "localhost":
        return False
    ips = await _resolve_all_ips(host)
    if not ips:
        return False  # unresolvable -> fail closed, don't let it through by default
    return not any(_is_blocked_ip(ip) for ip in ips)


async def resolve_validated_ip(hostname, allow_private_targets=False):
    """
    Returns ONE validated-safe IP string for `hostname`, or None if none
    of its resolved addresses pass the check (or it doesn't resolve at
    all). This is the IP-pinning primitive: callers should CONNECT to
    this exact returned IP, not re-resolve the hostname a second time —
    re-resolving is exactly the gap that lets DNS rebinding work.
    """
    if hostname.lower() == "localhost" and not allow_private_targets:
        return None
    ips = await _resolve_all_ips(hostname)
    if allow_private_targets:
        return ips[0] if ips else None
    for ip in ips:
        if not _is_blocked_ip(ip):
            return ip
    return None
