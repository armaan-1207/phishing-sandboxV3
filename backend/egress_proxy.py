"""
Local IP-pinning egress proxy — closes the SSRF DNS-rebinding gap.

THE GAP THIS CLOSES: `is_target_allowed()` resolves a hostname and
checks the result, then Playwright/Chromium is told to navigate.
Chromium does its OWN, separate DNS resolution when it actually
connects. Those are two different lookups — a DNS server that returns
one IP to the first query and a different one to the second (classic
DNS rebinding) can pass the check with a safe IP and then have the
browser actually connect to something else entirely (e.g. a cloud
metadata endpoint). The per-request `context.route()` recheck in
phishing_sandbox_scan.py shrinks this window a lot, but doesn't remove
it — there's still a real gap between Python's resolution and
Chromium's own subsequent one.

HOW THIS CLOSES IT: point a browser context at this proxy
(`new_context(proxy={"server": "http://127.0.0.1:<port>"})`). It
resolves the target hostname ITSELF, validates the result, and CONNECTS
DIRECTLY TO THAT VALIDATED IP — the same resolution that gets checked
is the one that gets used, with no second lookup in between for an
attacker's DNS server to flip. Chromium never resolves the
destination's hostname at all in this configuration.

SCOPE: a minimal HTTP forward proxy supporting CONNECT (HTTPS — the
overwhelming majority of real traffic) and plain absolute-URI HTTP. Not
general-purpose — no auth, no caching, just resolve -> validate ->
connect -> splice bytes. That's all this job needs.

TESTED: in isolation, against a local fake-metadata listener (confirms
blocking) and a real public site over loopback (confirms the tunnel
actually works end-to-end, including TLS through it) — see the test run
in this conversation. NOT tested against an actual live DNS-rebinding
attack — that needs a real authoritative DNS server under attacker
control deliberately flip-flopping responses, which isn't something
this environment can stand up. The protection follows from the design
(one resolution, used directly, no second lookup), not from having
reproduced the attack and watched it fail.

KNOWN TRADE-OFF: when `upstream_proxy` is set (chaining through a
caller-supplied residential proxy, e.g. for anti-cloaking), IP-pinning
on the FINAL hop is necessarily given up — the upstream proxy does its
own resolution, which this code has no visibility into. The target's
hostname is still validated before chaining at all, so a private/
internal target is still rejected; what's lost in that mode specifically
is protection against the upstream proxy itself being rebinding-tricked.

PATCH NOTES (post-audit-review fix):
  - M4: `_handle_plain_http`'s early-return error paths (400/403/502)
    wrote a response but never awaited `client_writer.drain()` before
    returning. Without draining, the write can still be sitting in the
    asyncio transport's internal buffer when the connection is torn
    down by the caller/finally block, and the client may never actually
    see the response. Every early return in that function now drains
    before returning, matching the pattern `_handle_connect` already
    used correctly.
"""

import asyncio
import logging
from urllib.parse import urlparse

try:
    from backend.ssrf_guard import resolve_validated_ip
except ImportError:
    from ssrf_guard import resolve_validated_ip

logger = logging.getLogger("phishing_sandbox.egress_proxy")

DEFAULT_PORT = 3128


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    except Exception as e:
        logger.debug("egress proxy pipe ended: %s", e)
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _handle_connect(client_reader, client_writer, host, port, upstream_proxy, allow_private_targets):
    validated_ip = await resolve_validated_ip(host, allow_private_targets=allow_private_targets)
    if validated_ip is None:
        logger.warning("egress proxy blocked CONNECT to %s:%s (no validated public IP)", host, port)
        client_writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        await client_writer.drain()
        return

    try:
        if upstream_proxy:
            up_host, up_port = upstream_proxy
            upstream_reader, upstream_writer = await asyncio.open_connection(up_host, up_port)
            upstream_writer.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            await upstream_writer.drain()
            response = await upstream_reader.readuntil(b"\r\n\r\n")
            if b"200" not in response.split(b"\r\n", 1)[0]:
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await client_writer.drain()
                return
        else:
            # The core case: connect directly to the EXACT IP just
            # validated. No second hostname resolution happens here.
            upstream_reader, upstream_writer = await asyncio.open_connection(validated_ip, port)
    except Exception as e:
        logger.warning("egress proxy could not connect upstream for %s:%s: %s", host, port, e, exc_info=True)
        client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await client_writer.drain()
        return

    client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await client_writer.drain()

    await asyncio.gather(
        _pipe(client_reader, upstream_writer),
        _pipe(upstream_reader, client_writer),
        return_exceptions=True,
    )


async def _handle_plain_http(client_reader, client_writer, request_line, headers_blob,
                              upstream_proxy, allow_private_targets):
    """The much rarer plain-HTTP-via-proxy case (absolute-URI request line)."""
    try:
        method, target, _ = request_line.split(" ", 2)
    except ValueError:
        client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await client_writer.drain()
        return

    parsed = urlparse(target)
    host, port = parsed.hostname, (parsed.port or 80)
    if not host:
        client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await client_writer.drain()
        return

    validated_ip = await resolve_validated_ip(host, allow_private_targets=allow_private_targets)
    if validated_ip is None:
        logger.warning("egress proxy blocked HTTP request to %s (no validated public IP)", host)
        client_writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        await client_writer.drain()
        return

    connect_to = upstream_proxy if upstream_proxy else (validated_ip, port)
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(*connect_to)
    except Exception as e:
        logger.warning("egress proxy could not connect upstream for %s: %s", host, e, exc_info=True)
        client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await client_writer.drain()
        return

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    out_line = request_line if upstream_proxy else f"{method} {path} HTTP/1.1"
    upstream_writer.write((out_line + "\r\n").encode() + headers_blob)
    await upstream_writer.drain()

    await asyncio.gather(
        _pipe(client_reader, upstream_writer),
        _pipe(upstream_reader, client_writer),
        return_exceptions=True,
    )


async def _handle_client(client_reader, client_writer, upstream_proxy, allow_private_targets):
    try:
        request_line_bytes = await client_reader.readline()
        if not request_line_bytes:
            return
        request_line = request_line_bytes.decode(errors="ignore").strip()

        headers_blob = b""
        while True:
            line = await client_reader.readline()
            headers_blob += line
            if line in (b"\r\n", b""):
                break

        if request_line.upper().startswith("CONNECT"):
            _, target, _ = request_line.split(" ", 2)
            host, _, port_str = target.partition(":")
            port = int(port_str) if port_str else 443
            await _handle_connect(client_reader, client_writer, host, port,
                                  upstream_proxy, allow_private_targets)
        else:
            await _handle_plain_http(client_reader, client_writer, request_line, headers_blob,
                                      upstream_proxy, allow_private_targets)
    except Exception as e:
        logger.debug("egress proxy client handler ended: %s", e)
    finally:
        try:
            client_writer.close()
        except Exception:
            pass


async def start_egress_proxy(port=DEFAULT_PORT, upstream_proxy=None, allow_private_targets=False):
    """
    upstream_proxy: optional (host, port) tuple to chain through after
    validating the target (e.g. a residential proxy for anti-cloaking —
    see scan_url's `proxy` parameter). See the "KNOWN TRADE-OFF" note
    in this module's docstring for what's given up in that mode.
    """
    server = await asyncio.start_server(
        lambda r, w: _handle_client(r, w, upstream_proxy, allow_private_targets),
        host="127.0.0.1", port=port,
    )
    logger.info("Egress proxy listening on 127.0.0.1:%s%s", port,
                f" (chained to upstream {upstream_proxy})" if upstream_proxy else "")
    return server
