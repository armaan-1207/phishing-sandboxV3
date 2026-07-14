"""
Shared fixtures for Sandbox Team's test suite.

Scope reminder (see README.md "Team ownership boundary"): this suite
covers phishing_sandbox_scan.py, ssrf_guard.py, egress_proxy.py, and
their direct collaborators (brand_phash.py, since it's post-detonation
telemetry on the sandbox's own screenshot output). It deliberately does
NOT cover app.py or quick_heuristics.py — those are Backend Team's
orchestration layer, not detonation/instrumentation/isolation.

Tests marked `@pytest.mark.integration` need a real Chromium install
and/or real network access. Run everything else with:
    pytest -m "not integration"

PATCH NOTES (post-audit-review fix):
  - H5: `browser.close()` and `playwright.stop()` used to run as two
    unguarded sequential statements after `yield`. If `browser.close()`
    raised (e.g. the browser process already died mid-test), `stop()`
    was skipped entirely, leaking the Playwright driver process for the
    rest of the test run. Both teardown calls now run inside a
    try/finally so `stop()` always executes even if `close()` fails.
"""

import sys
from pathlib import Path

import pytest

# Make `backend` importable as a package regardless of where pytest is
# invoked from (`from backend.X import Y`, run from the repo root).
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
async def chromium_browser():
    """
    A real Chromium instance, one per test. (Session-scoped would be
    faster, but a session-scoped async fixture paired with pytest-
    asyncio's default per-test event loop is a well-known way to hang —
    the fixture's connection ends up bound to a different loop than the
    test using it. Trading a few seconds of repeated launches for not
    hanging the suite.)
    """
    from playwright.async_api import async_playwright

    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(
        headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"],
    )
    try:
        yield browser
    finally:
        # NESTED try/finally, not two sequential awaits -- if
        # browser.close() itself raises (e.g. the browser process
        # already crashed/died mid-test), a flat "await close(); await
        # stop()" would skip stop() entirely, leaking the Playwright
        # driver process for the rest of the test run. This guarantees
        # stop() always runs, even when close() fails.
        try:
            await browser.close()
        finally:
            await playwright.stop()
