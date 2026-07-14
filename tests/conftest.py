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
    yield browser
    await browser.close()
    await playwright.stop()
