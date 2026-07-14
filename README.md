# Phishing Sandbox — Stage 5 Detonation Engine

A single-purpose Docker container: give it a URL, it opens the page in
headless Chromium, takes screenshots, extracts telemetry (DOM, network,
forms, TLS, evasion techniques, QR codes, brand-impersonation matches),
and writes the result as JSON. No browser extension, no VNC, no
persistent API service, no database — just a CLI tool in a container
that does one job and exits.

For how this connects to the rest of the pipeline (Backend Team's own
Celery/Redis/API layer, via a shared Docker volume), see
[`DOCKER_ARCHITECTURE_IDEATION.md`](DOCKER_ARCHITECTURE_IDEATION.md).

For real, tested starting-point code for that Backend/Celery layer
(kept working but explicitly **not** part of this container), see
[`handoff_reference/`](handoff_reference/README.md).

---

## What's in this repo

```
phishing-sandbox/
  backend/
    phishing_sandbox_scan.py   the detonation engine + CLI entrypoint
    ssrf_guard.py               resolves + blocks private/internal targets
    egress_proxy.py             IP-pinning local proxy (closes DNS-rebinding gap)
    brand_phash.py              perceptual-hash brand-impersonation matching
    build_reference_set.py      one-time helper to build your own brand hash set
  docker/
    Dockerfile                  minimal: headless Chromium, no Xvfb/VNC/extras
    docker-compose.yml           single service, shared output volume
    requirements.txt             sandbox-only dependencies
  tests/                        Sandbox Team's own test suite (pytest)
  handoff_reference/             NOT part of the image -- see its own README
  DOCKER_ARCHITECTURE_IDEATION.md   multi-container connection plan
```

## Running it

```bash
cd docker
docker compose build

# One-off scan, JSON printed to stdout:
docker compose run --rm sandbox https://example.com

# Write JSON + screenshots into a shared volume (the pattern
# DOCKER_ARCHITECTURE_IDEATION.md describes for connecting this to
# Backend Team's own worker/queue):
docker compose run --rm sandbox https://example.com --output-dir /app/output
```

Or without compose:

```bash
docker build -f docker/Dockerfile -t sandbox:latest .
docker run --rm sandbox:latest https://example.com
docker run --rm -v shared_scans:/app/output sandbox:latest \
    https://example.com --output-dir /app/output
```

Or fully local, no Docker at all (useful for development):

```bash
pip install -r docker/requirements.txt
playwright install chromium
python backend/phishing_sandbox_scan.py https://example.com
```

### CLI options

```
python backend/phishing_sandbox_scan.py <url> [options]

  --out PATH                 write JSON to this exact file (atomic write)
  --output-dir DIR            write JSON + screenshots into DIR using
                              scan_<id>-based filenames (the shared-volume
                              pattern -- see DOCKER_ARCHITECTURE_IDEATION.md)
  --timeout MS                navigation timeout, default 45000
  --request-id ID              correlation ID to stamp on the output
                              (pass your queue job's own ID here)
  --challenge-wait SECONDS     max time to wait for a bot-challenge page
                              to self-clear, default 10 (headless-only --
                              no human/VNC exists to solve anything harder)
  --proxy URL                 route through a proxy, e.g. for anti-cloaking
  --no-human-sim               disable the mouse/scroll simulation
  --probe-credentials          OFF by default -- submits a decoy credential
                              and checks for a post-submit domain change;
                              only use on targets already flagged suspicious
  --allow-private-targets      bypass the SSRF guard (local testing only)
```

### Output shape

One JSON object per scan, with these top-level sections:
`scans`, `pages`, `screenshots`, `network_activity`, `browser_events`,
`tls_connection`, `form_metrics`, `dom_content`, `phishing_signals`,
plus list-tables `evasion`, `headers`, `downloads`, `redirects`, and a
`timeline` of what happened during the scan (useful for debugging --
check this first if a result looks unexpectedly empty). Full field-by-
field documentation is in `phishing_sandbox_scan.py`'s own top
docstring.

---

## Security model

- **SSRF guard** (`ssrf_guard.py`): resolves every target hostname and
  refuses to navigate if any resolved IP is private, loopback,
  link-local, multicast, or reserved -- covers cloud metadata endpoints,
  the Docker bridge gateway, and localhost.
- **Egress proxy** (`egress_proxy.py`): closes the DNS-rebinding gap the
  SSRF guard alone can't -- a hostname could resolve to a safe IP during
  Python's check and something else moments later during Chromium's own
  separate resolution. The proxy makes resolution and connection the
  same atomic operation, so there's no second lookup for an attacker's
  DNS to flip.
- **Container hardening** (`docker-compose.yml`): non-root user,
  `cap_drop: ALL`, `no-new-privileges`, memory/CPU/PID limits. Chromium
  runs with `--no-sandbox` to match -- its own internal sandbox wants
  capabilities this container deliberately doesn't have; the
  container/non-root boundary is the real isolation layer, same
  tradeoff Playwright's own official Docker images make.
- **Download handling**: capped at 25MB/file, quarantined or discarded
  -- a malicious page spamming downloads can't fill the container's disk.

---

## Test suite

```bash
pip install -r tests/requirements-test.txt
playwright install chromium

pytest -m "not integration"   # fast, no browser/network needed
pytest -m integration          # needs real Chromium + real network
pytest                          # everything
```

29 tests, all passing (`handoff_reference/` has its own separate suite
of 41 -- see its README). Covers: SSRF blocking, the egress proxy's
IP-pinning property (proved structurally, not just observed), QR
decoding, brand-hash matching, and three real heuristic false-positive
bugs found by testing against live sites (see below) -- all with
permanent regression tests, not just fixed ad hoc.

---

## Real bugs found and fixed, with evidence

Three false-positive bugs were found by actually running scans against
real sites (github.com, and a reported false positive on wikipedia.org)
rather than by inspection alone -- each confirmed, fixed, and given a
regression test:

**1. JS obfuscation score conflated minification with malicious intent.**
Raw character-entropy scored GitHub's completely ordinary, legitimate
webpack bundle at 0.846 -- near the 1.0 ceiling, indistinguishable from
actual obfuscated code. Fixed with `compute_js_obfuscation_score()`: strips
long base64/data-URI blobs before computing entropy (they inflate
entropy without being code logic at all), recalibrates the entropy
range, and blends in concrete indicators real obfuscators use
(eval/Function-constructor combined with encoded-string unpacking,
known packer signatures, dense hex/unicode escape runs) instead of
trusting entropy alone. Re-tested: legitimate bundle now scores 0.177;
a synthetic packer-pattern payload scores 0.889 -- correctly separated.

**2. Cloaking check used fragile raw-text comparison with no length
guard.** Two independent page loads of the same URL can legitimately
differ even under the same user agent (rotating content, cache
variance, A/B tests) -- reported as a false positive on wikipedia.org.
Fixed with word-token Jaccard similarity (robust to reordering,
unlike positional character-sequence matching), a minimum-content-length
guard (returns `None`/undetermined rather than a confident answer built
on a block/error page), and a more conservative threshold. Verified
against three synthetic cases: legitimate content variance -> not
flagged, too-short content -> undetermined, genuine cloaking -> still
correctly caught.

**3. Bot-challenge detection matched raw HTML, not visible text.**
A real scan of github.com falsely flagged an active bot-challenge --
traced to the substring `"captcha"` matching inside a feature-flag name
(`"octocaptcha_origin_optimization"`) buried in an inline script's JSON
config, nowhere any user would ever see it. Fixed by checking
`page.inner_text("body")` (rendered visible text) instead of raw
`page.content()` -- script/style contents and hidden config blobs never
appear there. Confirmed fixed against the real site; existing
self-clearing-challenge tests still pass since real challenge text
lives in visible body content.

---

## Audit-driven fixes: WebSocket SSRF bypass, context leak, and four smaller issues

A codebase audit reported six findings, each verified against the real
code (and, where possible, against real running behavior) before
fixing — one turned out to already be claimed-fixed-but-wasn't, and
verifying the audit's most serious finding surfaced a second, more
consequential gap the audit itself didn't catch.

**WebSocket SSRF bypass (the serious one).** Confirmed empirically: a
malicious page's `new WebSocket('ws://127.0.0.1:PORT/')` call succeeds
completely, with Playwright's `context.route()` SSRF recheck never
even being invoked for it — proved by registering a route handler that
blocks *everything* and watching the WebSocket connection go through
regardless, actual data received. `context.route()` genuinely does not
see WebSocket traffic at all. Verifying this surfaced something the
audit didn't mention: **this CLI is now the only entrypoint into the
sandbox container** (the FastAPI service that used to start an egress
proxy moved to `handoff_reference/`, outside this image), and the CLI
never started one itself — meaning every real invocation of this
container was fully exposed to this bypass, not just a theoretical
edge case. Fixed two ways: (1) confirmed the egress proxy *does*
correctly intercept and block WebSocket connections, since it operates
at the actual network/CONNECT layer rather than Playwright's
request-interception layer; (2) `_run_cli_scan()` now starts its own
egress proxy automatically before every scan (skipped only when
`--allow-private-targets` is explicitly passed for local testing).
Both properties — the block itself, and the CLI wiring it up
automatically — have permanent regression tests.

**Context leak in `check_cloaking`.** Confirmed: `normal_ctx`/`bot_ctx`
were only closed on the line immediately after a successful
`goto()`/`inner_text()` call — an exception on either navigation (a
realistic, frequent occurrence: a timeout on a slow/ad-heavy site)
skipped the corresponding `close()` entirely, with no cleanup path at
all. Fixed with a per-context `try`/`finally`. Verified directly: forced
a navigation failure and confirmed zero contexts remain open on the
shared browser afterward, both for a first-navigation failure and a
second-navigation-only failure.

**`networkidle` → `load` in `check_cloaking`.** Confirmed: both
navigations used `wait_until="networkidle"` with a 20s timeout, and
tracking/ad-heavy sites send background requests indefinitely — this
routinely burned the *full* 20s on both navigations, up to 40s of pure
overhead per scan for a check that only needs the page's own rendered
text. Fixed by switching to `wait_until="load"`. The main detonation's
own navigation deliberately keeps `networkidle` — Stage 5 genuinely
needs full network telemetry there; only the two cloaking-comparison
navigations changed. Verified genuine cloaking is still detected and
non-cloaked pages still aren't falsely flagged under the new wait state.

**pyzbar import crash on missing native library.** The audit claimed
this was already fixed (`except (ImportError, OSError)`) — the actual
code still had a bare `except ImportError:`, which doesn't catch the
`OSError`/`FileNotFoundError` `ctypes` raises when pyzbar's native zbar
library fails to load (e.g. a local Windows dev run without the system
zbar package — a documented supported path in this README). Applied
the fix that was claimed-but-missing.

**Hardcoded `/tmp` paths.** `DOWNLOAD_QUARANTINE_DIR` and both
screenshot path constructions used a literal `"/tmp/..."`, which
doesn't exist by default on Windows. Switched to
`tempfile.gettempdir()` throughout — behaviorally identical inside the
Linux container, more robust for local dev elsewhere.

**Screenshot timeout, with an added partial-capture improvement.**
Added an explicit 5s timeout to both `page.screenshot()` calls
(Playwright's default is 30s and includes waiting for web fonts to
load — a page whose fonts come from a CDN this sandbox's own SSRF
guard blocks would otherwise hang for up to 30s per call). Went one
step further than the audit's recommendation: the two screenshots are
now captured independently rather than in one shared `try`/`except` —
previously, a full-page-screenshot timeout discarded a homepage
screenshot that had already succeeded and existed on disk, the same
"don't throw away partial success" issue already fixed elsewhere in
this file for navigation failures.

## What changed, and why (build history)

**Headless-only, no VNC/extension.** Earlier iterations of this project
included a browser extension gatekeeper, a VNC-over-WebSocket viewer
for interactive CAPTCHA-solving, and a persistent FastAPI service with
Redis-backed triage tiers. All of that was Backend/Frontend Team
territory being built in the wrong place -- this container now does
exactly one thing. `wait_for_challenge_to_clear` still detects bot
challenges and gives them a short window to self-clear (some
lightweight gates resolve with no interaction at all), but there's no
human/VNC to solve anything harder -- that's reported via
`phishing_signals.unresolved_interactivity` for whatever orchestrates
this container to act on.

**Partial-failure capture.** A navigation timeout used to mean zero
data captured at all -- DOM snapshot and screenshots were both gated on
a fully-successful `page.goto()`. Now both are attempted regardless
(each already had its own error handling): a stealthy phishing kit
intentionally lagging its assets to exhaust a scanner's timeout no
longer results in an empty result on exactly the page most worth
capturing.

**Atomic output writes.** `--output-dir` writes to a temp file and
`os.rename()`s it into place, so a file-watcher on the consuming side
(Backend Team's future Celery worker) never reads a partially-written
JSON payload mid-scan.

**SSRF hardening** (`ssrf_guard.py`, `egress_proxy.py`): a bounded,
TTL'd DNS cache (the original was unbounded -- a real memory leak at
scale) and the IP-pinning egress proxy described above, both tested --
the proxy's core property (no second, unvalidated hostname resolution)
proved structurally by mocking the resolver and confirming the proxy
dials exactly the validated IP.

**Anti-evasion**: real stealth via `playwright-stealth` (broader
coverage than a hand-rolled property patch -- WebGL vendor,
`chrome.runtime` presence, permissions.query override), Bezier-curve
mouse movement instead of linear interpolation, staggered scrolling.

**Bounded recursive QR detonation**: a decoded QR payload that's itself
a URL gets scanned too (reusing the same browser), capped at one extra
hop so a QR-to-QR chain can't trigger unbounded detonations.

**A resource leak found via testing, not inspection**: the browser
*context* a scan creates was never explicitly closed in pooled-browser
mode (only implicitly, via `browser.close()`, on the path where a scan
owns its own browser). Found because a test's `egress_proxy.wait_closed()`
hung indefinitely -- it waits for every connection the server ever
spawned to finish, and one was still open. Fixed by closing the context
unconditionally at the end of every scan.

**DB-alignment middleware bugs**: a draft "compatibility layer" meant
to translate this container's JSON output for a specific Postgres
schema had a bug that would have silently nulled `source_url`,
`scan_start_time`, and `scan_end_time` on every real scan (it read
field names -- `.get("url")`, `.get("created_at")` -- that don't exist;
the real ones already matched the schema and needed no transform at
all), plus a signal-loss bug (replacing a real detection signal with
data already stored elsewhere). Corrected version, tested against real
scan output, lives in `handoff_reference/db_alignment_middleware.py` --
not part of this container, since persistence is a database/backend
concern, but kept working since Backend Team will need exactly this.
