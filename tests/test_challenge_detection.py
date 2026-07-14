"""
Integration tests for wait_for_challenge_to_clear -- needs a real
Chromium instance, hence @pytest.mark.integration throughout.

The second test here is a REGRESSION test for a real bug found during
manual verification in this project's development: page.content() can
throw "page is navigating" exactly at the moment a challenge page
reloads itself after clearing (the actual mechanism real Cloudflare
challenges use) -- and the original implementation treated that
transient error as permanent failure, giving up right when the real
answer was one poll away. See README.md's changelog for the full story.
"""

import pytest
from aiohttp import web

from backend.phishing_sandbox_scan import wait_for_challenge_to_clear

pytestmark = pytest.mark.integration


@pytest.fixture
async def http_server():
    """Yields a function to register a handler and start a server, returning its port."""
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


async def test_challenge_that_never_clears_is_reported_unresolved(chromium_browser, http_server):
    async def never_clears(request):
        return web.Response(
            text="<html><body>Checking your browser before accessing example.com. "
                 "Cloudflare Ray ID: abc123</body></html>",
            content_type="text/html",
        )

    port = await http_server(never_clears)
    page = await chromium_browser.new_page()
    await page.goto(f"http://127.0.0.1:{port}/", timeout=5000)

    detected, resolved = await wait_for_challenge_to_clear(page, max_wait_seconds=3)

    assert detected is True
    assert resolved is False
    await page.close()


async def test_challenge_that_self_reloads_and_clears_is_reported_resolved(chromium_browser, http_server):
    """Regression test for the page.content()-throws-mid-navigation bug."""
    state = {"count": 0}

    async def clears_on_second_request(request):
        state["count"] += 1
        if state["count"] < 2:
            return web.Response(
                text='<html><head><meta http-equiv="refresh" content="1"></head>'
                     "<body>Checking your browser... cloudflare challenge-running</body></html>",
                content_type="text/html",
            )
        return web.Response(text="<html><body>Welcome to the real page!</body></html>",
                             content_type="text/html")

    port = await http_server(clears_on_second_request)
    page = await chromium_browser.new_page()
    await page.goto(f"http://127.0.0.1:{port}/", timeout=5000)

    detected, resolved = await wait_for_challenge_to_clear(page, max_wait_seconds=5)

    assert detected is True
    assert resolved is True, (
        "if this regresses, check that the polling loop CONTINUES past a "
        "transient page.content() error during navigation, rather than "
        "breaking out and reporting unresolved"
    )
    await page.close()


async def test_page_with_no_challenge_returns_immediately(chromium_browser, http_server):
    async def clean_page(request):
        return web.Response(text="<html><body>Nothing suspicious here.</body></html>",
                             content_type="text/html")

    port = await http_server(clean_page)
    page = await chromium_browser.new_page()
    await page.goto(f"http://127.0.0.1:{port}/", timeout=5000)

    detected, resolved = await wait_for_challenge_to_clear(page, max_wait_seconds=3)

    assert detected is False
    assert resolved is True
    await page.close()


async def test_challenge_marker_in_hidden_config_is_not_a_false_positive(chromium_browser, http_server):
    """
    Regression test for a real bug found during manual verification: a
    completely normal page (github.com) was flagged as showing a bot
    challenge because raw page.content() included the substring
    "captcha" inside an inline script's JSON feature-flag config
    ("octocaptcha_origin_optimization") -- nowhere any user would ever
    see it, and nothing to do with an actual challenge being shown.
    Fixed by checking visible rendered text (inner_text) instead of raw
    HTML, since script/style contents and hidden config blobs never
    appear there. This test reproduces that exact shape of false
    positive with a synthetic page.
    """
    async def page_with_hidden_captcha_string(request):
        return web.Response(
            text=(
                "<html><body>"
                "<h1>Completely normal page</h1>"
                "<p>Nothing suspicious here, just a regular website with real content "
                "that has nothing to do with any bot verification or security check.</p>"
                "<script>"
                "window.__featureFlags = {"
                '"octocaptcha_origin_optimization": true, '
                '"some_other_flag": false'
                "};"
                "</script>"
                "</body></html>"
            ),
            content_type="text/html",
        )

    port = await http_server(page_with_hidden_captcha_string)
    page = await chromium_browser.new_page()
    await page.goto(f"http://127.0.0.1:{port}/", timeout=5000)

    detected, resolved = await wait_for_challenge_to_clear(page, max_wait_seconds=2)

    assert detected is False, (
        "a 'captcha'-like substring buried in a script's JSON config, invisible to "
        "any real user, must not be treated as an active bot-challenge"
    )
    assert resolved is True
    await page.close()
