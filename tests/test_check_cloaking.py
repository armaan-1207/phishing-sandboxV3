"""
Tests for check_cloaking() in phishing_sandbox_scan.py.

No test file previously existed for this function at all -- these were
written after an audit found (and this project confirmed, via direct
testing) two real issues:

1. A context leak: normal_ctx/bot_ctx were only closed on the line
   immediately after a successful goto()/inner_text() call. An
   exception on either navigation (a timeout on a slow/ad-heavy site is
   a frequent, realistic trigger) skipped the close() entirely, with no
   cleanup path. Fixed with a per-context try/finally.
2. Both navigations used wait_until="networkidle" with a 20s timeout --
   tracking-heavy sites send background requests indefinitely, so this
   routinely hit the FULL 20s timeout on both navigations, adding up to
   40s of pure overhead to every scan. Fixed by switching to
   wait_until="load", which only waits for the page's own resources,
   not for ad networks to go quiet.
"""

import pytest
from aiohttp import web

from backend.phishing_sandbox_scan import check_cloaking

pytestmark = pytest.mark.integration


@pytest.fixture
async def http_server():
    runners = []

    async def _start(handler):
        app = web.Application()
        app.router.add_get("/", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        runners.append(runner)
        return port

    yield _start

    for runner in runners:
        await runner.cleanup()


async def test_no_context_leak_when_first_navigation_fails(chromium_browser):
    """Regression test for the confirmed leak: an unreachable target
    (connection refused, not just a slow one) must not leave a
    BrowserContext open on the shared browser afterward."""
    contexts_before = len(chromium_browser.contexts)

    result = await check_cloaking(
        chromium_browser, "http://127.0.0.1:1/", (1366, 768), allow_private_targets=True,
    )

    contexts_after = len(chromium_browser.contexts)
    assert result is None
    assert contexts_after == contexts_before, (
        f"context leak: {contexts_after - contexts_before} context(s) left open "
        "after a failed navigation"
    )


async def test_no_context_leak_when_second_navigation_fails(chromium_browser, http_server):
    """The first navigation (normal UA) succeeds and its context closes
    correctly; the second (bot UA) must not leak even though the first
    one's cleanup already ran."""
    async def normal_page(request):
        return web.Response(text="<html><body>" + ("hello world " * 50) + "</body></html>",
                             content_type="text/html")

    port = await http_server(normal_page)
    contexts_before = len(chromium_browser.contexts)

    # Real target for the normal-UA pass; force the bot-UA pass to hit a
    # dead port by using an egress_proxy_port that isn't actually
    # listening -- simplest reliable way to make only the SECOND
    # navigation fail without needing UA-dependent server logic.
    result = await check_cloaking(
        chromium_browser, f"http://127.0.0.1:{port}/", (1366, 768),
        allow_private_targets=True, egress_proxy_port=1,
    )

    contexts_after = len(chromium_browser.contexts)
    assert contexts_after == contexts_before, (
        f"context leak: {contexts_after - contexts_before} context(s) left open"
    )


async def test_genuine_cloaking_still_detected_with_load_wait(chromium_browser, http_server):
    """Confirms switching networkidle -> load didn't break real
    detection -- a page serving meaningfully different content to the
    bot UA must still be flagged."""
    async def cloaking_handler(request):
        ua = request.headers.get("User-Agent", "")
        if "Googlebot" in ua:
            body = (
                "Welcome to our completely normal blog about gardening tips and recipes "
                "for the home cook interested in seasonal vegetables and herbs grown locally "
                "in your own backyard using sustainable organic composting methods and techniques "
                "passed down through generations of experienced gardeners across the region"
            )
        else:
            body = (
                "Enter your bank account credentials below to verify your identity urgent "
                "security alert action required immediately or your account will be suspended "
                "permanently today please provide your username password and social security "
                "number to confirm ownership and avoid unauthorized access to your funds now"
            )
        return web.Response(text=f"<html><body>{body}</body></html>", content_type="text/html")

    port = await http_server(cloaking_handler)
    result = await check_cloaking(
        chromium_browser, f"http://127.0.0.1:{port}/", (1366, 768), allow_private_targets=True,
    )
    assert result is True


async def test_non_cloaked_page_not_flagged_with_load_wait(chromium_browser, http_server):
    async def same_content(request):
        body = ("This is the same ordinary page content regardless of who requests it, "
                "with enough text to clear the minimum comparable length guard in both "
                "the normal and bot user agent renders of this identical page.")
        return web.Response(text=f"<html><body>{body}</body></html>", content_type="text/html")

    port = await http_server(same_content)
    result = await check_cloaking(
        chromium_browser, f"http://127.0.0.1:{port}/", (1366, 768), allow_private_targets=True,
    )
    assert result is False
