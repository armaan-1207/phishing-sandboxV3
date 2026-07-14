"""
End-to-end smoke test: a real scan_url() detonation against a real
site, through both the browser pool and the egress proxy together.
Needs real Chromium + real network access -- @pytest.mark.integration.

This isn't trying to assert much about CONTENT (that's heuristic and
expected to vary) -- it's asserting that the whole pipeline runs
without raising, returns the full 13-table-shaped result, and that the
egress-proxy-routed traffic actually reached the real site.

PATCH NOTES (post-audit-review fix):
  - EXPECTED_TOP_LEVEL_KEYS updated to match the real sandbox_db DDL:
    "tls_connection" -> "tls_connections", "evasion" -> "evasion_techniques",
    "headers" -> "security_headers". scan_url()'s output was
    intentionally changed to align with those exact table names -- this
    test's expectations were stale against the shorthand names used
    before that alignment, not the other way around.
"""

import pytest

from backend.egress_proxy import start_egress_proxy
from backend.phishing_sandbox_scan import scan_url

pytestmark = pytest.mark.integration

EXPECTED_TOP_LEVEL_KEYS = {
    "scans", "pages", "screenshots", "network_activity", "browser_events",
    "tls_connections", "form_metrics", "dom_content", "phishing_signals",
    "evasion_techniques", "security_headers", "downloads", "redirects", "timeline",
}


async def test_full_scan_against_real_site_via_pool_and_egress_proxy(chromium_browser):
    proxy_server = await start_egress_proxy(port=0)
    proxy_port = proxy_server.sockets[0].getsockname()[1]

    try:
        result = await scan_url(
            "https://github.com",
            timeout_ms=20000,
            simulate_human=False,  # keep the test fast; behavior covered separately
            browser=chromium_browser,
            egress_proxy_port=proxy_port,
        )
    finally:
        proxy_server.close()
        await proxy_server.wait_closed()

    assert "error" not in result
    assert EXPECTED_TOP_LEVEL_KEYS.issubset(result.keys())
    assert result["pages"]["final_url"].startswith("https://github.com")
    assert result["scans"]["scan_id"]
    assert result.get("ssrf_blocked_requests") is None, "a real site shouldn't trip the SSRF guard"
    assert isinstance(result["evasion_techniques"], list) and len(result["evasion_techniques"]) > 0
    assert isinstance(result["timeline"], list) and len(result["timeline"]) > 0


async def test_scan_refuses_a_private_target_before_ever_touching_the_browser(chromium_browser):
    result = await scan_url(
        "http://127.0.0.1:9999/internal-admin",
        browser=chromium_browser,
    )

    assert result.get("error") == "target_not_allowed"
    assert "timeline" in result
