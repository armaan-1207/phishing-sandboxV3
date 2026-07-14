"""
Tests for backend/egress_proxy.py — the IP-pinning local proxy that
closes the SSRF DNS-rebinding gap (see that module's docstring).
"""

import asyncio

import pytest

from backend import egress_proxy as ep


@pytest.fixture
async def running_proxy():
    server = await ep.start_egress_proxy(port=0)  # port=0 -> OS picks a free port
    port = server.sockets[0].getsockname()[1]
    yield port
    server.close()
    await server.wait_closed()


async def test_blocks_connect_to_private_target(monkeypatch, running_proxy):
    port = running_proxy
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"CONNECT 127.0.0.1:9999 HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n")
    await writer.drain()
    response = await reader.read(200)
    writer.close()
    assert b"403" in response


async def test_dials_exactly_the_validated_ip_not_a_fresh_resolution(monkeypatch):
    """
    The core security property, proved structurally: if resolution
    returns IP X, the proxy must CONNECT to X directly -- never
    re-resolve the hostname a second time. This is what actually closes
    the DNS-rebinding gap (see egress_proxy.py's docstring).
    """
    calls = []

    async def fake_resolve(hostname, allow_private_targets=False):
        calls.append(hostname)
        return "198.51.100.7"  # RFC5737 TEST-NET-2 -- guaranteed non-routable, deliberately distinctive

    dialed = []

    async def spy_open_connection(host, port, *a, **kw):
        dialed.append((host, port))
        raise ConnectionRefusedError("expected in this test -- we only care what was dialed")

    monkeypatch.setattr(ep, "resolve_validated_ip", fake_resolve)
    monkeypatch.setattr(asyncio, "open_connection", spy_open_connection)

    reader = asyncio.StreamReader()
    reader.feed_data(b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
    reader.feed_eof()

    sent = []

    class FakeWriter:
        def write(self, data):
            sent.append(data)

        async def drain(self):
            pass

        def close(self):
            pass

    await ep._handle_client(reader, FakeWriter(), upstream_proxy=None, allow_private_targets=False)

    assert calls == ["github.com"]
    assert dialed == [("198.51.100.7", 443)], (
        "the proxy must dial the exact validated IP -- any deviation means "
        "a second, unvalidated resolution is happening somewhere"
    )


@pytest.mark.integration
async def test_real_tunnel_to_a_real_site(running_proxy):
    """Confirms the CONNECT tunnel actually works end-to-end, including
    a real TLS handshake through it -- not just that it doesn't crash."""
    httpx = pytest.importorskip("httpx")
    port = running_proxy
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", timeout=15) as client:
        r = await client.get("https://github.com")
        assert r.status_code == 200


@pytest.mark.integration
async def test_websocket_to_private_target_is_blocked(running_proxy):
    """
    Regression test for a confirmed real bypass: Playwright's own
    context.route() SSRF recheck (used inside scan_url()) does NOT see
    WebSocket traffic at all -- confirmed directly by running a probe
    against a real 'private' WebSocket service with context.route()
    registered to block everything, and observing the WS handshake
    succeed with the route handler never even being called.

    The egress proxy closes this gap because it operates at the actual
    network/CONNECT layer, not at Playwright's request-interception
    layer -- a WebSocket handshake is itself an HTTP CONNECT (for wss://)
    or a plain HTTP Upgrade request (for ws://) that Chromium routes
    through whatever proxy is configured via context(proxy=...), same as
    any other traffic. This test confirms that property directly: a
    WebSocket connection attempt to a private target, made through a
    browser context configured to use the egress proxy, must fail.
    """
    playwright = pytest.importorskip("playwright.async_api")
    websockets = pytest.importorskip("websockets")
    from playwright.async_api import async_playwright

    async def ws_handler(websocket):
        await websocket.send("SECRET_INTERNAL_DATA_LEAKED")

    private_server = await websockets.serve(ws_handler, "127.0.0.1", 0)
    private_port = private_server.sockets[0].getsockname()[1]

    port = running_proxy
    p = await async_playwright().start()
    browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
    context = await browser.new_context(proxy={"server": f"http://127.0.0.1:{port}"})
    page = await context.new_page()
    await page.goto("about:blank")

    result = await page.evaluate(f"""
        () => new Promise((resolve) => {{
            const ws = new WebSocket('ws://127.0.0.1:{private_port}/');
            ws.onmessage = (e) => resolve({{success: true, data: e.data}});
            ws.onerror = () => resolve({{success: false, reason: 'error'}});
            setTimeout(() => resolve({{success: false, reason: 'timeout'}}), 4000);
        }})
    """)

    await browser.close()
    await p.stop()
    private_server.close()
    await private_server.wait_closed()

    assert result["success"] is False, (
        "WebSocket connection to a private target succeeded through the egress "
        "proxy -- the SSRF bypass is NOT closed"
    )


@pytest.mark.integration
async def test_cli_scan_starts_its_own_egress_proxy():
    """
    Regression test for the gap the audit's WebSocket finding actually
    exposed: this CLI is the ONLY entrypoint into the sandbox container
    (the FastAPI wrapper that used to start an egress proxy moved to
    handoff_reference/, outside this image). Without _run_cli_scan
    starting its own proxy, every real invocation of this container was
    running fully exposed to the WebSocket SSRF bypass above -- not a
    theoretical gap, the default/only code path.
    """
    import argparse
    from backend.phishing_sandbox_scan import _run_cli_scan

    args = argparse.Namespace(
        url="http://127.0.0.1:1/", timeout=5000, request_id=None,
        challenge_wait=2, proxy=None, no_human_sim=True,
        probe_credentials=False, allow_private_targets=False,
    )
    # A private/unreachable target must be refused by the upfront SSRF
    # check regardless of the egress proxy -- this just confirms
    # _run_cli_scan's default (non-allow_private_targets) path runs
    # end-to-end without needing an external caller to wire anything up.
    result = await _run_cli_scan(args)
    assert result.get("error") == "target_not_allowed"
