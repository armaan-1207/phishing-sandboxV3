"""
Phishing Sandbox Scanner — Stage 5 (Sandbox Detonation)
=========================================================
Captures the fields defined in the FINAL normalized schema (the
"SANDBOX — 3NF & BCNF" diagram: 13 tables, scan_id as the shared FK)
for a single submitted URL, using Playwright (Chromium) + the Chrome
DevTools Protocol (CDP). This is the heaviest, final-tier component of
a larger pipeline (CyberIntel -> Visual/OCR/DOM -> LightGBM fusion ->
Credential Protection -> this sandbox), triggered only on already-
suspicious URLs.

OUTPUT SHAPE
------------
    {
      "scans": {...},              "pages": {...},
      "screenshots": {...},        "network_activity": {...},
      "browser_events": {...},     "tls_connection": {...},
      "form_metrics": {...},       "dom_content": {...},
      "phishing_signals": {...},
      "evasion": [ {...}, ... ],
      "headers": [ {...}, ... ],
      "downloads": [ {...}, ... ],
      "redirects": [ {...}, ... ],
      "timeline": [ {...}, ... ],   # debugging aid, see below
      "credential_probe": {...},    # only present if probe_credentials=True
    }

DEBUGGING
---------
`timeline` is always included: a chronological list of
{"t": iso_timestamp, "event": "..."} entries for every major step,
including anything that failed and was swallowed. Check this first
when a scan comes back with unexpectedly empty fields — most failure
modes (challenge gate, SSRF block, navigation timeout, CDP hiccup) show
up here even though the scan still completes and returns a result
rather than raising.

Server-side logs go through the standard `logging` module under the
"phishing_sandbox" logger — set LOG_LEVEL=DEBUG in the environment for
verbose output.

SECURITY
--------
This script visits attacker-controlled URLs by design, which makes it
an SSRF engine unless explicitly fenced. Before navigating ANYWHERE
(initial URL, and every redirect/subresource via context.route), the
target hostname is resolved and rejected if it lands on a private,
loopback, link-local, multicast, reserved, or unspecified address —
this specifically covers cloud metadata endpoints (169.254.169.254),
the Docker bridge gateway, and localhost. Override with
allow_private_targets=True only for local testing against a
deliberately internal test fixture.

WHAT THIS DOES vs. WHAT IT DOESN'T DO
--------------------------------------
- Every field tagged "Headless Browser" / "Browser DevTools Protocol" /
  "Sandbox Orchestrator" is captured directly using a documented,
  standard technique (DOM queries, CDP events, init scripts).
- Every "Local Python Logic" field is computed here from data this
  script already captured (domain comparisons, regex scans, hashing).
- SEVEN fields/behaviors are first-pass heuristics, not validated
  production detectors: cloaking_detected, js_obfuscation_score,
  evasion_technique_flags, qr_code_detected, fingerprinting_api_count,
  unresolved_interactivity, and the credential-redirect probe. They
  are clearly marked "HEURISTIC:" below. Tune against real traffic
  before trusting them in production.
- External Cyber Threat Intelligence fields (VirusTotal, Shodan,
  AbuseIPDB, crt.sh, OTX, IPinfo, favicon_hash) are NOT in this
  script — they belong to the separate Stage 1 CyberIntel component.

PERFORMANCE: pass a pre-launched `browser` (a Playwright Browser
instance, e.g. from app.py's pooled singleton) to skip the ~1-3s
Chromium process-launch cost per scan — only a lightweight, isolated
BrowserContext gets created/torn down per call in that mode. Omit it
(default) to launch+close a throwaway browser per call, e.g. for the
CLI/standalone case below.

QR RECURSION: a QR code's decoded URL is, itself, just another
candidate phishing target — when found, it's recursively passed back
through this same function (SSRF-guarded, same as anything else),
bounded by `max_qr_recursion_depth` (default 1 hop) so a page that
QR-links to another QR-linking page can't trigger unbounded detonations.

INSTALL (run on a machine with normal internet access — this sandbox's
network is restricted and can't download the Chromium binary):
    pip install -r docker/requirements.txt
    playwright install chromium
    # pyzbar also needs the system zbar library:
    #   Debian/Ubuntu: sudo apt-get install libzbar0
    #   macOS:         brew install zbar

RUN:
    python phishing_sandbox_scan.py https://example.com
    python phishing_sandbox_scan.py https://example.com --headful --out result.json
"""

import argparse
import asyncio
import json
import logging
import math
import os
import random
import re
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from playwright.async_api import async_playwright
from playwright_stealth import Stealth

try:
    import cv2
    from pyzbar import pyzbar
    QR_AVAILABLE = True
except (ImportError, OSError):
    # OSError specifically covers pyzbar's native zbar library failing
    # to load via ctypes (e.g. libzbar-64.dll missing on a local Windows
    # dev environment without the system zbar package installed) --
    # ctypes raises OSError/FileNotFoundError for that, not ImportError,
    # so a bare `except ImportError` let it crash the entire module
    # import (and therefore the whole CLI, and test collection) instead
    # of just disabling the QR-detection feature as intended.
    QR_AVAILABLE = False

try:
    # Package mode — how this module is imported when run as part of
    # the `backend` package (`from backend.phishing_sandbox_scan import
    # scan_url`).
    from backend.brand_phash import BrandMatcher
    BRAND_PHASH_AVAILABLE = True
except ImportError:
    try:
        # Standalone CLI mode — running this file directly
        # (`python phishing_sandbox_scan.py ...`), where sys.path[0] is
        # this file's own directory, so `backend` isn't a visible package
        # but brand_phash.py sitting right next to this file is.
        from brand_phash import BrandMatcher
        BRAND_PHASH_AVAILABLE = True
    except ImportError:
        BRAND_PHASH_AVAILABLE = False

logger = logging.getLogger("phishing_sandbox")
logger.addHandler(logging.NullHandler())

_STEALTH = Stealth()
# Reference set is optional — see brand_phash.py / build_reference_set.py.
# Looked up relative to this file so it works regardless of cwd.
_BRAND_REFERENCE_PATH = os.path.join(os.path.dirname(__file__), "reference_hashes.json")
try:
    _BRAND_MATCHER = (
        BrandMatcher.from_file(_BRAND_REFERENCE_PATH) if BRAND_PHASH_AVAILABLE else None
    )
except Exception as e:
    # Defense-in-depth: BrandMatcher.from_file() already handles bad
    # JSON and malformed individual hash entries internally, but this
    # runs at MODULE IMPORT TIME — any other unexpected failure here
    # (e.g. a permissions error) would otherwise crash the entire
    # container's startup, not just disable brand matching. Confirmed
    # directly: before from_file()'s own fix, a single malformed hex
    # entry in reference_hashes.json took down the whole module import.
    logger.warning("Brand-impersonation matching disabled — failed to load %s: %s",
                    _BRAND_REFERENCE_PATH, e)
    _BRAND_MATCHER = None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SECURITY_HEADER_KEYS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

# HEURISTIC: known anti-debug / anti-sandbox JS patterns.
# Every key here becomes one row per scan in the Evasion table
# (technique_name + evasion_technique_flags 0/1) — a dense feature
# matrix, not a sparse "only matched ones" list.
EVASION_PATTERNS = {
    "devtools_size_check": r"outerWidth\s*-\s*innerWidth|outerHeight\s*-\s*innerHeight",
    "debugger_trap": r"\bdebugger\s*;",
    "webdriver_check": r"navigator\.webdriver",
    "headless_ua_check": r"HeadlessChrome",
    "phantom_check": r"window\.callPhantom|_phantom",
    "console_timing_trap": r"console\.(log|debug)\s*\([^)]*Date\.now",
}

# HEURISTIC: JS-side redirect triggers (distinct from a <meta refresh> tag).
JS_REDIRECT_PATTERN = re.compile(
    r"location\.(href\s*=|replace\(|assign\()|window\.location\s*="
)

USER_AGENT_BOT = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

# Markers that indicate a bot-challenge gate (Cloudflare, generic CAPTCHA,
# etc.) rather than the real page. Used by the interactive wait-loop below.
CHALLENGE_MARKERS = (
    "cloudflare", "captcha", "challenge-running",
    "verify you are human", "checking your browser",
)

# Obvious, fixed honeytoken values for the opt-in credential-redirect probe.
# Never real user data. Deliberately unrealistic so nothing downstream
# mistakes this for a genuine credential if it ever leaks into a log.
DECOY_EMAIL = "sandbox-probe@example-research.invalid"
DECOY_PASSWORD = "Sandbox-Probe-NOT-A-REAL-Credential-1!"

# A malicious page can trigger downloads as a resource-exhaustion vector
# (fill the container's disk across many scans) just as easily as it can
# as an actual payload-delivery vector. Cap per-file size and quarantine
# anything kept, instead of leaving Playwright's temp download files to
# accumulate indefinitely.
MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024  # 25MB
DOWNLOAD_QUARANTINE_DIR = os.path.join(tempfile.gettempdir(), "sandbox_downloads")


# ---------------------------------------------------------------------------
# SSRF guard — primitives live in ssrf_guard.py (shared with egress_proxy.py)
# ---------------------------------------------------------------------------

try:
    from backend.ssrf_guard import is_target_allowed, resolve_validated_ip
except ImportError:
    from ssrf_guard import is_target_allowed, resolve_validated_ip

try:
    from backend.egress_proxy import start_egress_proxy
except ImportError:
    from egress_proxy import start_egress_proxy


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def domain_of(url):
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return None


def shannon_entropy(text):
    """HEURISTIC building block for js_obfuscation_score."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return entropy


# Long base64/data-URI/hex blobs (embedded images, fonts, source maps)
# inflate character-level entropy without being "obfuscated code logic"
# at all -- strip them before scoring so a page that just happens to
# embed a data: URI icon doesn't get flagged the same as packed/encoded
# malicious JS.
_LONG_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/=_\-]{120,}")

# Concrete obfuscation indicators, not just "the text looks dense."
# Legitimate minified/bundled JS (webpack, terser, etc.) is dense but
# essentially never combines eval()/Function() with encoded-string
# unpacking the way real obfuscators (e.g. the common "eval(function(p,a,c,k,e,d)"
# packer) do.
_OBFUSCATION_INDICATORS = {
    "eval_call": re.compile(r"\beval\s*\("),
    "function_constructor": re.compile(r"new\s+Function\s*\(|\bFunction\s*\(\s*['\"]"),
    "unescape_or_decode": re.compile(r"\bunescape\s*\(|\bdecodeURIComponent\s*\(\s*escape"),
    "atob_call": re.compile(r"\batob\s*\("),
    "packer_signature": re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e"),
    "dense_hex_escapes": re.compile(r"(\\x[0-9a-fA-F]{2}){8,}"),
    "dense_unicode_escapes": re.compile(r"(\\u[0-9a-fA-F]{4}){8,}"),
}


def compute_js_obfuscation_score(inline_script_text):
    """
    HEURISTIC, composite: character-entropy alone can't distinguish
    "densely minified for production" from "packed/encoded to hide
    intent" -- confirmed directly against a real site: raw entropy
    scored 0.846 (near max) on GitHub's ordinary webpack bundle, a false
    positive on completely legitimate code. This blends entropy
    (computed AFTER stripping long base64/data-URI/hex blobs, which
    inflate entropy without being code logic at all) with explicit
    indicators real obfuscators actually use (eval/Function-constructor
    combined with encoded-string unpacking, known packer signatures,
    dense hex/unicode escape runs) rather than trusting entropy alone.

    Still a HEURISTIC -- recalibrate the weights/thresholds below
    against real labeled examples before trusting this in production,
    same caveat as every other heuristic in this file.
    """
    if not inline_script_text:
        return 0.0

    stripped = _LONG_BLOB_PATTERN.sub("", inline_script_text)
    entropy = shannon_entropy(stripped)
    # Recalibrated range: legitimate dense/minified JS (after blob
    # stripping) typically sits ~4.2-4.8 bits/char; genuinely
    # packed/encoded payloads tend to push higher, ~5.2+. Widened vs.
    # the original (3.0, 2.5) band, which put ordinary bundles near the
    # ceiling.
    entropy_component = min(max((entropy - 4.2) / 1.3, 0.0), 1.0)

    indicator_hits = sum(
        1 for pattern in _OBFUSCATION_INDICATORS.values() if pattern.search(inline_script_text)
    )
    # Any single concrete indicator matters more than entropy alone; the
    # packer signature specifically is treated as near-conclusive.
    if _OBFUSCATION_INDICATORS["packer_signature"].search(inline_script_text):
        indicator_component = 1.0
    else:
        indicator_component = min(indicator_hits / 3.0, 1.0)

    # Entropy alone (even at its new, more conservative calibration) is
    # still just a density signal -- weight it below the concrete
    # indicators rather than letting it drive the score on its own.
    score = 0.35 * entropy_component + 0.65 * indicator_component
    return round(min(score, 1.0), 3)


def classify_window_opens(events):
    """
    Splits CDP Page.windowOpen events into (popup_count, new_tab_count).

    - window.open() with no user click  -> userGesture=False           -> popup
    - <a target="_blank"> click         -> userGesture=True, no size   -> new tab
    - window.open() with width=/height= -> userGesture=True, has size  -> popup
    """
    popups, tabs = 0, 0
    for evt in events:
        features = evt.get("windowFeatures", [])
        has_explicit_size = any(f.startswith("width=") or f.startswith("height=")
                                 for f in features)
        user_gesture = evt.get("userGesture", True)
        if has_explicit_size or not user_gesture:
            popups += 1
        else:
            tabs += 1
    return popups, tabs


async def close_quietly(page_obj):
    """Close a spawned popup/tab as soon as possible so a malicious site
    spamming window.open() can't pile up browser pages during the scan."""
    try:
        await page_obj.wait_for_timeout(200)
        await page_obj.close()
    except Exception:
        pass


async def wait_for_challenge_to_clear(page, max_wait_seconds):
    """
    If the page is showing a bot-challenge (Cloudflare/CAPTCHA/etc.), poll
    its content instead of sleeping a fixed timeout — resumes the instant
    the page self-clears (some lightweight "checking your browser" gates
    resolve on their own within a few seconds with no interaction at
    all). This is a headless-only container with no VNC/human in the
    loop, so `max_wait_seconds` should stay short — anything that
    doesn't self-clear within it is reported via the returned
    `resolved=False`, and this function makes no further attempt.

    Checks the page's VISIBLE RENDERED TEXT (inner_text), not the raw
    HTML. Confirmed as a real false-positive source: raw page.content()
    on a completely normal github.com load matched the "captcha" marker
    because the page embeds a feature-flag name
    ("octocaptcha_origin_optimization") inside an inline script's JSON
    config blob -- nowhere a user would ever see it, and nothing to do
    with an actual challenge being shown. Rendered visible text
    naturally excludes script/style contents, hidden config blobs, and
    HTML comments, which is exactly where that kind of incidental
    substring match comes from.

    Returns (challenge_detected: bool, resolved: bool). Whatever calls
    this container's output JSON can use (detected and not resolved) —
    exposed as `phishing_signals.unresolved_interactivity` — to route
    that URL to a separate interactive-review process if one exists.
    """
    try:
        text = (await page.inner_text("body")).lower()
    except Exception:
        return False, False

    detected = any(marker in text for marker in CHALLENGE_MARKERS)
    if not detected:
        return False, True

    for _ in range(max_wait_seconds):
        await page.wait_for_timeout(1000)
        try:
            text = (await page.inner_text("body")).lower()
        except Exception as e:
            # This fires almost exactly when a navigation is in flight --
            # i.e. almost exactly when the challenge page is reloading
            # itself after clearing. Treating it as a permanent failure
            # (the previous behavior here) means the single most likely
            # moment to see this error is also the moment it incorrectly
            # gives up, right when the real answer is one poll away.
            # Skip this poll and try again next second instead.
            logger.debug("wait_for_challenge_to_clear: inner_text() unavailable mid-poll (%s), retrying", e)
            continue
        if not any(marker in text for marker in CHALLENGE_MARKERS):
            return True, True

    return True, False


def _quadratic_bezier_points(p0, p1, p2, n):
    """n points along a quadratic Bezier curve from p0 through control
    point p1 to p2 — a curved, human-like path rather than Playwright's
    default linear interpolation between two points."""
    points = []
    for i in range(1, n + 1):
        t = i / n
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t ** 2 * p2[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t ** 2 * p2[1]
        points.append((x, y))
    return points


async def simulate_human_behavior(page):
    """
    Some phishing kits gate their real payload behind a cheap "is there
    a human here" check — no mouse movement, no scroll, treat as a bot
    and serve a benign page instead. This moves the mouse along randomized
    quadratic-Bezier curves (not Playwright's default straight-line
    interpolation) and does a couple of staggered scroll passes — closer
    to how a real cursor and a real scroll session actually look. It is
    NOT a fingerprinting countermeasure and won't clear sophisticated
    bot-detection vendors — just enough motion to clear the cheapest
    behavioral checks.
    """
    try:
        viewport = page.viewport_size or {"width": 1366, "height": 768}
        w, h = max(viewport["width"] - 1, 1), max(viewport["height"] - 1, 1)

        current = (random.randint(0, w), random.randint(0, h))
        for _ in range(3):
            target = (random.randint(0, w), random.randint(0, h))
            # A control point off the straight line between current and
            # target gives the curve its bend, instead of a straight glide.
            control = (
                random.randint(0, w),
                random.randint(0, h),
            )
            for x, y in _quadratic_bezier_points(current, control, target, n=random.randint(8, 16)):
                await page.mouse.move(x, y)
                await page.wait_for_timeout(random.randint(8, 25))
            current = target
            await page.wait_for_timeout(random.randint(80, 220))

        # A couple of staggered scroll passes (down, a little back up, down
        # again) rather than one single wheel event — closer to how
        # someone actually reading a page scrolls, and more likely to
        # trigger scroll-linked lazy-load/IntersectionObserver scripts a
        # single jump wouldn't.
        for delta in (random.randint(250, 500), -random.randint(50, 150), random.randint(300, 600)):
            await page.mouse.wheel(0, delta)
            await page.wait_for_timeout(random.randint(150, 350))
    except Exception as e:
        logger.debug("simulate_human_behavior skipped: %s", e)


async def probe_credential_redirect(page, settle_ms=8000):
    """
    OPT-IN, OFF BY DEFAULT (probe_credentials=True to enable). Detects
    phishing kits that wait for ANY submitted credential before
    redirecting to a separate live credential-harvesting backend —
    a static page load alone won't trigger that.

    Fills any detected password field (and an adjacent email/text field)
    with a fixed, obviously-fake honeytoken value — never real user
    data — submits the form, and checks whether the browser ends up on
    a different domain afterward.

    Only enable this on targets a prior pipeline stage already flagged
    as suspicious: unlike the rest of this scan, it actively interacts
    with the target's backend rather than just observing.
    """
    try:
        password_input = await page.query_selector("input[type=password]")
        if not password_input:
            return {"attempted": False}

        email_input = await page.query_selector("input[type=email], input[type=text]")
        pre_submit_url = page.url

        if email_input:
            await email_input.fill(DECOY_EMAIL)
        await password_input.fill(DECOY_PASSWORD)

        submit_btn = await page.query_selector("input[type=submit], button[type=submit]")
        if submit_btn:
            await submit_btn.click()
        else:
            await password_input.press("Enter")

        await page.wait_for_timeout(settle_ms)
        post_submit_url = page.url

        return {
            "attempted": True,
            "pre_submit_url": pre_submit_url,
            "post_submit_url": post_submit_url,
            "redirected_to_new_domain": domain_of(pre_submit_url) != domain_of(post_submit_url),
        }
    except Exception as e:
        logger.warning("probe_credential_redirect failed: %s", e, exc_info=True)
        return {"attempted": False, "error": str(e)}


async def fast_forward_js_timers(cdp_session, budget_ms=30000):
    """
    HEURISTIC / OPT-IN, not wired into the default flow. Defeats JS-side
    "wait N minutes before showing the payload" tricks using Chrome
    DevTools Protocol's real virtual-time feature
    (Emulation.setVirtualTimePolicy), rather than hooking NTP packets or
    patching Sleep() at the OS level — those solve a Windows-malware
    sandbox's problem, not a single Chromium page's timer queue.

    CAVEAT: virtual time freezes network loading too, so only call this
    AFTER initial navigation has settled.
    """
    try:
        await cdp_session.send("Emulation.setVirtualTimePolicy", {
            "policy": "advance",
            "budget": budget_ms,
        })
    except Exception as e:
        logger.debug("fast_forward_js_timers not supported here: %s", e)


# ---------------------------------------------------------------------------
# Init script injected BEFORE any page JS runs.
# ---------------------------------------------------------------------------
INIT_SCRIPT = """
(() => {
  // Automation-fingerprint stealth (navigator.webdriver, plugins,
  // languages, WebGL vendor, chrome.runtime presence, etc.) is handled
  // by playwright-stealth's apply_stealth_async() on the context, not
  // here — that covers far more fingerprint vectors than a hand-rolled
  // 3-property patch would. This init script now only owns the
  // counters below.

  window.__scanCounters = {
    permission_requests: [],
    clipboard_read_attempts: 0,
    clipboard_write_attempts: 0,
    fingerprinting_api_count: 0,
  };

  if (window.Notification && Notification.requestPermission) {
    const orig = Notification.requestPermission.bind(Notification);
    Notification.requestPermission = function(...args) {
      window.__scanCounters.permission_requests.push('notification');
      return orig(...args);
    };
  }

  if (navigator.geolocation && navigator.geolocation.getCurrentPosition) {
    const orig = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
    navigator.geolocation.getCurrentPosition = function(...args) {
      window.__scanCounters.permission_requests.push('location');
      return orig(...args);
    };
  }

  if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    const orig = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getUserMedia = function(constraints) {
      if (constraints && constraints.video) window.__scanCounters.permission_requests.push('camera');
      if (constraints && constraints.audio) window.__scanCounters.permission_requests.push('microphone');
      return orig(constraints);
    };
  }

  if (navigator.clipboard) {
    if (navigator.clipboard.readText) {
      const orig = navigator.clipboard.readText.bind(navigator.clipboard);
      navigator.clipboard.readText = function(...args) {
        window.__scanCounters.clipboard_read_attempts++;
        return orig(...args);
      };
    }
    if (navigator.clipboard.writeText) {
      const orig = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = function(...args) {
        window.__scanCounters.clipboard_write_attempts++;
        return orig(...args);
      };
    }
  }

  try {
    if (window.HTMLCanvasElement) {
      const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
      HTMLCanvasElement.prototype.toDataURL = function(...args) {
        window.__scanCounters.fingerprinting_api_count++;
        return origToDataURL.apply(this, args);
      };
    }
    if (window.CanvasRenderingContext2D) {
      const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
      CanvasRenderingContext2D.prototype.getImageData = function(...args) {
        window.__scanCounters.fingerprinting_api_count++;
        return origGetImageData.apply(this, args);
      };
    }
    if (window.WebGLRenderingContext) {
      const origGetParameter = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function(...args) {
        window.__scanCounters.fingerprinting_api_count++;
        return origGetParameter.apply(this, args);
      };
    }
    if (window.AudioContext || window.OfflineAudioContext) {
      const Ctor = window.AudioContext || window.OfflineAudioContext;
      const wrapped = function(...args) {
        window.__scanCounters.fingerprinting_api_count++;
        return new Ctor(...args);
      };
      wrapped.prototype = Ctor.prototype;
      if (window.AudioContext) window.AudioContext = wrapped;
      if (window.OfflineAudioContext) window.OfflineAudioContext = wrapped;
    }
  } catch (e) { /* best-effort, ignore hook failures */ }
})();
"""

DOM_SNAPSHOT_SCRIPT = """
() => {
  const qsa = (sel) => Array.from(document.querySelectorAll(sel));
  const origin = location.origin;

  const links = qsa('a[href]');
  const externalLinks = links.filter(a => {
    try { return new URL(a.href, origin).origin !== origin; }
    catch (e) { return false; }
  });

  const iframes = qsa('iframe');
  const hiddenIframes = iframes.filter(f => {
    const style = getComputedStyle(f);
    return style.display === 'none' || style.visibility === 'hidden' ||
           f.width === '0' || f.height === '0' ||
           f.offsetWidth === 0 || f.offsetHeight === 0;
  });

  const forms = qsa('form');
  const formActionUrls = forms.map(f => f.action || origin);  // internal use only, not stored
  const crossDomainFormCount = formActionUrls.filter(u => {
    try { return new URL(u, origin).origin !== origin; }
    catch (e) { return false; }
  }).length;

  const allInputs = qsa('input');
  const passwordInputs = allInputs.filter(el => (el.getAttribute('type') || '').toLowerCase() === 'password');
  const emailInputs = allInputs.filter(el => (el.getAttribute('type') || '').toLowerCase() === 'email');
  const nonCredentialTypes = allInputs
    .filter(el => {
      const t = (el.getAttribute('type') || 'text').toLowerCase();
      return t !== 'password' && t !== 'email' && t !== 'submit';
    })
    .map(el => (el.getAttribute('type') || 'text').toLowerCase());

  const scripts = qsa('script');
  const inlineScriptText = scripts.filter(s => !s.src).map(s => s.textContent).join('\\n');
  const externalScriptSrcs = scripts.filter(s => s.src).map(s => s.src);
  const externalScriptsOffDomain = externalScriptSrcs.filter(src => {
    try { return new URL(src, origin).origin !== origin; }
    catch (e) { return false; }
  });

  const navTiming = performance.getEntriesByType('navigation')[0];
  const pageLoadTimeMs = navTiming ? Math.round(navTiming.loadEventEnd - navTiming.startTime) : null;

  const hasMetaRefresh = qsa('meta[http-equiv]').some(
    m => (m.getAttribute('http-equiv') || '').toLowerCase() === 'refresh'
  );

  return {
    page_title: document.title || "",
    page_language: document.documentElement.lang || null,
    page_load_time_ms: pageLoadTimeMs,
    dom_element_count: qsa('*').length,

    password_field_count: passwordInputs.length,
    email_field_count: emailInputs.length,
    non_credential_field_count: nonCredentialTypes,
    submit_button_count: qsa('input[type=submit], button[type=submit]').length,
    cross_domain_form_count: crossDomainFormCount,

    visible_text_length: (document.body ? document.body.innerText.length : 0),
    hyperlink_count: links.length,
    external_hyperlink_count: externalLinks.length,
    iframe_count: iframes.length,
    hidden_iframe_count: hiddenIframes.length,
    script_count: scripts.length,
    external_script_count: externalScriptsOffDomain.length,

    has_meta_refresh: hasMetaRefresh,
    inline_script_text: inlineScriptText,

    counters: window.__scanCounters || {},
  };
}
"""


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

async def scan_url(url, timeout_ms=45000, viewport=(1366, 768), request_id=None,
                    challenge_wait_seconds=10, proxy=None,
                    storage_state=None, simulate_human=True,
                    probe_credentials=False, allow_private_targets=False,
                    browser=None, qr_recursion_depth=0, max_qr_recursion_depth=1,
                    egress_proxy_port=None):
    """
    This is a headless-only container — there is no Xvfb display, no
    VNC, and no human in the loop. Every scan runs headless.

    challenge_wait_seconds: max time to poll a detected bot-challenge
        page to see if it SELF-CLEARS (some lightweight "checking your
        browser" gates resolve on their own within a few seconds with
        no interaction at all). Short by design — with no human
        available to solve anything harder, waiting longer just delays
        the result. Whatever hasn't cleared by the timeout is reported
        via `phishing_signals.unresolved_interactivity` in the output
        JSON for whatever consumes this container's results to act on.
    proxy: optional proxy URL, e.g. "http://user:pass@host:port" — a
        residential proxy is the relevant fix for "phishing site sees a
        datacenter IP and serves a cloaked benign page instead."
    storage_state: optional Playwright storage_state dict/path (cookies +
        localStorage) handed off from an earlier pipeline stage's
        browser session, e.g. `await stage2_context.storage_state()`.
        Lets this scan continue the EXACT session that looked
        suspicious upstream, rather than starting fresh and risking a
        site that serves different content on a "second visit."
    simulate_human: Bezier-curve mouse movement + staggered scrolling
        before snapshotting, so cheap "no human activity = bot" checks
        don't gate the payload.
    probe_credentials: OFF by default. If True and a password field is
        found, submits a fixed decoy credential and checks for a
        post-submit domain change (see probe_credential_redirect). Only
        enable on targets already flagged suspicious upstream.
    allow_private_targets: bypass the SSRF guard. Only for local testing
        against a deliberately internal fixture — never in production.
    browser: optional pre-launched Playwright Browser (e.g. from a
        pooled singleton in app.py) — skips the ~1-3s Chromium
        process-launch cost per call; only a lightweight isolated
        BrowserContext is created/torn down here. Omit to launch+close
        a throwaway browser (default; used by the CLI below). Note:
        even in pool mode this still opens its own short-lived
        `async_playwright()` driver connection — only the expensive
        Chromium process launch is actually skipped, not that.
    qr_recursion_depth / max_qr_recursion_depth: a QR code's decoded
        payload is, itself, just another candidate phishing target —
        when one decodes to an http(s) URL, it's recursively scanned
        too (reusing the same browser), bounded by
        max_qr_recursion_depth (default: 1 extra hop) so a page that
        QR-links to another QR-linking page can't trigger unbounded
        detonations. Don't set qr_recursion_depth yourself — scan_url
        sets it on its own recursive call.
    egress_proxy_port: port of a running egress_proxy.py instance (see
        app.py's lifespan) — when set, ALL browser traffic routes
        through it instead of Chromium resolving destinations itself.
        This is what actually closes the SSRF DNS-rebinding gap (see
        egress_proxy.py's docstring); ignored if `proxy` is also set
        (a caller-supplied proxy takes priority — see the trade-off
        noted where context_kwargs["proxy"] is built, above).
    """
    timeline = []

    def mark(event):
        timeline.append({"t": now_iso(), "event": event})
        logger.info(event)

    network_events = []
    window_open_events = []
    downloads = []
    blocked_requests = []

    scan_id = str(uuid.uuid4())
    scan_start_time = now_iso()
    mark(f"scan started for {url}")

    if not await is_target_allowed(url, allow_private_targets):
        mark("REFUSED: target resolves to a private/internal/reserved address")
        logger.error("Refusing to scan disallowed target: %s", url)
        return {
            "error": "target_not_allowed",
            "detail": "URL resolves to a private/internal/reserved address; refusing to scan.",
            "scans": {
                "scan_id": scan_id, "source_url": url,
                "scan_start_time": scan_start_time, "scan_end_time": now_iso(),
                "request_id": request_id or str(uuid.uuid4()),
            },
            "timeline": timeline,
        }

    credential_probe_result = None

    async with async_playwright() as p:
        if browser is not None:
            owns_browser = False  # pooled — caller (app.py) owns its lifecycle
        else:
            owns_browser = True
            # --no-sandbox: Chromium's OWN internal sandbox wants Linux
            # capabilities (roughly CAP_SYS_ADMIN-equivalent) that we
            # deliberately do NOT grant this container (see
            # docker-compose.yml: cap_drop, non-root user). Without this
            # flag, Chromium fails to start in that hardened
            # configuration. This is the same tradeoff Playwright/
            # Puppeteer's own official Docker images make: the
            # CONTAINER boundary is the isolation layer here, not
            # Chromium's internal one. --disable-dev-shm-usage avoids
            # crashes on small /dev/shm if shm_size isn't honored by
            # whatever orchestrator ends up running this.
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
        context_kwargs = {
            "viewport": {"width": viewport[0], "height": viewport[1]},
            "accept_downloads": True,
        }
        if proxy:
            # Caller explicitly wants a specific upstream (e.g. a
            # residential proxy for anti-cloaking) — honor it directly.
            # KNOWN TRADE-OFF: this skips egress_proxy.py's IP-pinning for
            # this scan; the upfront is_target_allowed() check and the
            # per-request context.route() recheck below still apply, but
            # the DNS-rebinding window they don't fully close stays open
            # in this specific mode. See egress_proxy.py's docstring.
            context_kwargs["proxy"] = {"server": proxy}
        elif egress_proxy_port:
            # Default, safe path: Chromium never resolves the
            # destination's hostname itself at all — see
            # egress_proxy.py for why this is the actual fix for the
            # DNS-rebinding TOCTOU gap, not just another check.
            context_kwargs["proxy"] = {"server": f"http://127.0.0.1:{egress_proxy_port}"}
        if storage_state:
            context_kwargs["storage_state"] = storage_state
            mark("using handed-off session state from an earlier pipeline stage")
        context = await browser.new_context(**context_kwargs)
        try:
            await _STEALTH.apply_stealth_async(context)
            await context.add_init_script(INIT_SCRIPT)

            # SSRF guard, defense-in-depth: every request this context makes
            # (redirects, subresources, iframes — not just the initial nav)
            # gets the same private/internal-address check.
            async def _ssrf_guard_route(route):
                target = route.request.url
                if await is_target_allowed(target, allow_private_targets):
                    await route.continue_()
                else:
                    blocked_requests.append(target)
                    logger.warning("SSRF guard blocked request to %s", target)
                    await route.abort()

            await context.route("**/*", _ssrf_guard_route)

            page = await context.new_page()

            cdp = await context.new_cdp_session(page)
            await cdp.send("Page.enable")
            cdp.on("Page.windowOpen", lambda evt: window_open_events.append(evt))

            def on_new_page(pg):
                asyncio.create_task(close_quietly(pg))

            context.on("page", on_new_page)

            def on_request(req):
                network_events.append({"type": "request", "url": req.url,
                                        "resource_type": req.resource_type})

            async def on_response(resp):
                try:
                    headers = await resp.all_headers()
                except Exception:
                    headers = {}
                network_events.append({
                    "type": "response", "url": resp.url, "status": resp.status,
                    "headers": headers,
                })

            ws_count = {"n": 0}
            page.on("request", on_request)
            page.on("response", lambda r: asyncio.create_task(on_response(r)))
            page.on("websocket", lambda ws: ws_count.__setitem__("n", ws_count["n"] + 1))
            page.on("download", lambda d: downloads.append(d))

            main_response = None
            load_error = None
            try:
                main_response = await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                mark("initial navigation complete")
            except Exception as e:
                load_error = str(e)
                mark(f"navigation error: {e}")
                logger.warning("Navigation failed for %s: %s", url, e, exc_info=True)

            challenge_detected, challenge_resolved = False, True
            # No human/VNC in this simplified, headless-only container —
            # this is now a short SELF-CLEAR-ONLY wait (some lightweight JS
            # "checking your browser" gates resolve on their own within a
            # few seconds with no interaction at all). Anything that doesn't
            # self-clear is reported via unresolved_interactivity for
            # whatever consumes this container's output to act on. Not
            # gated on main_response — page.content() can still work on a
            # partially-loaded page, and a challenge gate is exactly the
            # kind of thing that might cause page.goto() to appear to hang.
            challenge_detected, challenge_resolved = await wait_for_challenge_to_clear(
                page, challenge_wait_seconds
            )
            if challenge_detected:
                mark(f"bot-challenge detected; self-cleared={challenge_resolved}")

            if simulate_human:
                await simulate_human_behavior(page)
                mark("human-behavior simulation done")

            await page.wait_for_timeout(1000)

            scan_end_time = now_iso() if main_response is not None else None

            final_url = None
            chain = []
            dom = {}
            counters = {}
            inline_script_text = ""
            has_meta_refresh = False
            sec = None
            main_headers = {}

            # These genuinely need a valid response object -- there's no
            # meaningful fallback for a redirect chain or TLS/header details
            # from a navigation that never got a response at all.
            if main_response is not None:
                final_url = page.url

                req = main_response.request
                seen = set()
                while req is not None:
                    if req.url not in seen:
                        chain.append(req.url)
                        seen.add(req.url)
                    req = req.redirected_from
                chain.reverse()

                try:
                    sec = await main_response.security_details()
                except Exception as e:
                    logger.debug("security_details unavailable: %s", e)

                try:
                    main_headers = {k.lower(): v for k, v in (await main_response.all_headers()).items()}
                except Exception as e:
                    logger.debug("response headers unavailable: %s", e)

            # DOM snapshot and screenshots are NOT gated on main_response
            # anymore. A page.goto() timeout means the FULL page lifecycle
            # (networkidle) never completed -- it does NOT mean the page
            # object has nothing rendered. A stealthy phishing kit that
            # intentionally lags asset loading to exhaust a scanner's
            # timeout would previously leave this container with zero
            # captured data on exactly the pages most worth capturing. Both
            # blocks already have their own try/except, so a genuinely blank
            # page just produces empty-but-present fields, not a crash.
            if page is not None:
                try:
                    dom = await page.evaluate(DOM_SNAPSHOT_SCRIPT)
                    counters = dom.pop("counters", {})
                    inline_script_text = dom.pop("inline_script_text", "")
                    has_meta_refresh = dom.pop("has_meta_refresh", False)
                    dom.pop("script_count", None)  # denominator only, not stored
                    mark("DOM snapshot captured")
                    if main_response is None:
                        mark("DOM snapshot captured from a PARTIAL/failed navigation "
                             "-- treat with extra caution, page never reached networkidle")
                except Exception as e:
                    mark(f"DOM snapshot failed: {e}")
                    logger.warning("DOM snapshot failed: %s", e, exc_info=True)
                if final_url is None:
                    # page.url still reflects wherever navigation got to,
                    # even on a timeout -- worth recording rather than
                    # leaving final_url null when we might know it.
                    try:
                        final_url = page.url
                    except Exception:
                        pass

            protocol_used = "HTTPS" if url.lower().startswith("https") else "HTTP"
            certificate_present = bool(sec)
            certificate_issuer = sec.get("issuer") if sec else None
            tls_version = sec.get("protocol") if sec else None
            certificate_issued_date = None
            if sec:
                valid_from = sec.get("validFrom")
                if valid_from:
                    certificate_issued_date = datetime.fromtimestamp(
                        valid_from, tz=timezone.utc
                    ).isoformat()

            home_path = os.path.join(tempfile.gettempdir(), f"{scan_id}_home.png")
            full_path = os.path.join(tempfile.gettempdir(), f"{scan_id}_full.png")
            # Explicit 5s timeout on each call: Playwright's default is 30s
            # and includes waiting for custom web fonts to finish loading. A
            # page whose fonts come from a CDN our own SSRF guard blocks (or
            # that's just slow/unreachable) would otherwise hang for up to
            # 30s on EACH of the two calls below.
            #
            # Captured independently rather than in one shared try/except —
            # a full-page screenshot timing out shouldn't discard a
            # homepage screenshot that already succeeded and exists on disk.
            try:
                await page.screenshot(path=home_path, timeout=5000)
            except Exception as e:
                home_path = None
                mark(f"homepage screenshot failed: {e}")
                logger.warning("Homepage screenshot failed: %s", e, exc_info=True)

            try:
                await page.screenshot(path=full_path, full_page=True, timeout=5000)
            except Exception as e:
                full_path = None
                mark(f"full-page screenshot failed: {e}")
                logger.warning("Full-page screenshot failed: %s", e, exc_info=True)

            if home_path or full_path:
                mark("screenshots captured" if main_response is not None
                     else "screenshots captured from a PARTIAL/failed navigation")

            # Opt-in active probe — runs AFTER passive metrics/screenshots are
            # captured, so it can never contaminate them with post-submit
            # state. Not gated on main_response: probe_credential_redirect
            # already safely no-ops if it finds no password field, and a
            # partial/timed-out page may still have rendered a real one.
            if probe_credentials:
                credential_probe_result = await probe_credential_redirect(page)
                mark(f"credential-redirect probe: {credential_probe_result.get('attempted')}")

            b64_pattern = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
            base64_encoded_script_count = len(b64_pattern.findall(inline_script_text))

            redirect_trigger_types = []
            if has_meta_refresh:
                redirect_trigger_types.append("meta_refresh")
            if JS_REDIRECT_PATTERN.search(inline_script_text):
                redirect_trigger_types.append("js_redirect")

            js_obfuscation_score = compute_js_obfuscation_score(inline_script_text)

            qr_code_detected = None
            qr_linked_scan = None
            if QR_AVAILABLE and full_path:
                qr_code_detected, qr_urls = detect_qr(full_path)
                if qr_urls and qr_recursion_depth < max_qr_recursion_depth:
                    # Recurse on at most the first decoded URL — a page with
                    # several QR codes shouldn't multiply detonation cost
                    # linearly; one extra hop is enough to catch the common
                    # "QR points at the real phishing page" pattern.
                    qr_target = qr_urls[0]
                    mark(f"QR code decoded to {qr_target}; recursing (depth {qr_recursion_depth + 1})")
                    qr_linked_scan = await scan_url(
                        qr_target,
                        timeout_ms=timeout_ms,
                        viewport=viewport,
                        proxy=proxy,
                        egress_proxy_port=egress_proxy_port,
                        simulate_human=simulate_human,
                        allow_private_targets=allow_private_targets,
                        browser=browser,  # reuse the same (possibly pooled) browser
                        qr_recursion_depth=qr_recursion_depth + 1,
                        max_qr_recursion_depth=max_qr_recursion_depth,
                    )
                elif qr_urls:
                    mark(f"QR code decoded to a URL but max recursion depth "
                         f"({max_qr_recursion_depth}) already reached; not following it")

            brand_match = None
            if _BRAND_MATCHER is not None and full_path:
                brand_match = _BRAND_MATCHER.match(full_path)
                if brand_match:
                    mark(f"brand-impersonation match: {brand_match['brand']} "
                         f"(similarity {brand_match['similarity']})")

            requests = [e for e in network_events if e["type"] == "request"]
            responses = [e for e in network_events if e["type"] == "response"]
            total_request_count = len(requests)

            req_domains = {domain_of(e["url"]) for e in requests if domain_of(e["url"])}
            unique_requested_domains = len(req_domains)
            page_domain = domain_of(final_url or url)
            third_party_domain_count = len([d for d in req_domains if d != page_domain])

            xhr_request_count = len([e for e in requests if e["resource_type"] in ("xhr", "fetch")])
            websocket_connection_count = ws_count["n"]

            popup_count, new_tab_count = classify_window_opens(window_open_events)

            downloads_rows = []
            for d in downloads:
                size = None
                quarantined_path = None
                try:
                    tmp_path = await d.path()
                    if tmp_path:
                        size = tmp_path.stat().st_size
                        if size <= MAX_DOWNLOAD_BYTES:
                            os.makedirs(DOWNLOAD_QUARANTINE_DIR, exist_ok=True)
                            quarantined_path = os.path.join(
                                DOWNLOAD_QUARANTINE_DIR,
                                f"{scan_id}_{uuid.uuid4().hex[:8]}_{d.suggested_filename}",
                            )
                            shutil.move(str(tmp_path), quarantined_path)
                        else:
                            # Over the cap: keep the recorded size as a signal,
                            # but don't let a malicious page fill the disk.
                            tmp_path.unlink(missing_ok=True)
                            mark(f"download over size cap discarded ({size} bytes)")
                except Exception as e:
                    logger.warning("Download handling failed for %s: %s",
                                    getattr(d, "suggested_filename", "?"), e, exc_info=True)
                downloads_rows.append({
                    "downloaded_id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "file_name": d.suggested_filename,
                    "file_size": size,
                    # Ops/debug field, not part of the DOWNLOADS table schema —
                    # drop this key before inserting if your DB column set is strict.
                    "quarantined_path": quarantined_path,
                })
            if downloads_rows:
                mark(f"{len(downloads_rows)} download(s) captured")

            redirects_rows = []
            for i, hop_url in enumerate(chain):
                status = next((r["status"] for r in responses if r["url"] == hop_url), None)
                redirects_rows.append({
                    "redirect_id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "hop_index": i,
                    "redirect_url": hop_url,
                    "http_status_code": status,
                })

            evasion_rows = [
                {
                    "technique_id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "technique_name": name,
                    "evasion_technique_flags": 1 if re.search(pat, inline_script_text) else 0,
                }
                for name, pat in EVASION_PATTERNS.items()
            ]

            headers_rows = [
                {
                    "header_id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "security_headers_present": h,
                }
                for h in SECURITY_HEADER_KEYS if h in main_headers
            ]

            cloaking_detected = None
            if final_url:
                try:
                    cloaking_detected = await check_cloaking(browser, final_url, viewport, allow_private_targets,
                                                              egress_proxy_port=egress_proxy_port)
                    mark("cloaking check complete")
                except Exception as e:
                    mark(f"cloaking check failed: {e}")
                    logger.warning("Cloaking check failed: %s", e, exc_info=True)

        finally:
            # In pool mode (owns_browser=False), the context this scan
            # created was never closed before -- only the owned-browser path
            # closed it (implicitly, via browser.close()). Every pooled scan
            # was leaking its context, and the connections it opened, for
            # the lifetime of the shared browser. Found via testing: a local
            # proxy's wait_closed() hung waiting for a connection that
            # belonged to exactly this leaked context. Moved into a real
            # finally: block wrapping the WHOLE scan body above (not just
            # placed after it) -- confirmed via audit that any uncaught
            # exception ANYWHERE in that ~340-line body would previously
            # skip this close() entirely, since it sat at the same level as
            # ordinary sequential code with no outer guarantee.
            try:
                await context.close()
            except Exception as e:
                logger.debug("context.close() failed (non-fatal): %s", e)

        if owns_browser:
            await browser.close()
        mark("scan finished")

    result = {
        "scans": {
            "scan_id": scan_id,
            "source_url": url,
            "scan_start_time": scan_start_time,
            "scan_end_time": scan_end_time,
            "request_id": request_id or str(uuid.uuid4()),
        },
        "pages": {
            "page_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "page_title": dom.get("page_title"),
            "final_url": final_url,
            "page_language": dom.get("page_language"),
            "page_load_time_ms": dom.get("page_load_time_ms"),
            "dom_element_count": dom.get("dom_element_count"),
        },
        "screenshots": {
            "screenshot_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "homepage_screenshot_path": home_path,
            "fullpage_screenshot_path": full_path,
        },
        "network_activity": {
            "network_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "total_request_count": total_request_count,
            "unique_requested_domains": unique_requested_domains,
            "third_party_domain_count": third_party_domain_count,
            "xhr_request_count": xhr_request_count,
            "websocket_connection_count": websocket_connection_count,
            "fingerprinting_api_count": counters.get("fingerprinting_api_count", 0),
        },
        "browser_events": {
            "event_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "popup_count": popup_count,
            "new_tab_count": new_tab_count,
            "permission_requests": counters.get("permission_requests", []),
            "clipboard_read_attempts": counters.get("clipboard_read_attempts", 0),
            "clipboard_write_attempts": counters.get("clipboard_write_attempts", 0),
        },
        "tls_connection": {
            "tls_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "protocol_used": protocol_used,
            "certificate_present": certificate_present,
            "certificate_issuer": certificate_issuer,
            "tls_version": tls_version,
            "certificate_issued_date": certificate_issued_date,
        },
        "form_metrics": {
            "form_stats_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "password_field_count": dom.get("password_field_count"),
            "email_field_count": dom.get("email_field_count"),
            "non_credential_field_count": dom.get("non_credential_field_count", []),
            "submit_button_count": dom.get("submit_button_count"),
            "cross_domain_form_count": dom.get("cross_domain_form_count"),
        },
        "dom_content": {
            "dom_stats_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "visible_text_length": dom.get("visible_text_length"),
            "hyperlink_count": dom.get("hyperlink_count"),
            "external_hyperlink_count": dom.get("external_hyperlink_count"),
            "external_script_count": dom.get("external_script_count"),
            "hidden_iframe_count": dom.get("hidden_iframe_count"),
            "iframe_count": dom.get("iframe_count"),
        },
        "phishing_signals": {
            "phish_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "base64_encoded_script_count": base64_encoded_script_count,
            "redirect_trigger_types": redirect_trigger_types,
            "qr_code_detected": qr_code_detected,
            "cloaking_detected": cloaking_detected,
            "js_obfuscation_score": js_obfuscation_score,
            # HEURISTIC: feeds the orchestrator's "unresolved interactivity"
            # modifier (doc suggestion #5) — true only if a challenge was
            # seen AND nobody/nothing cleared it within the wait window.
            "unresolved_interactivity": challenge_detected and not challenge_resolved,
            # Not part of the original 9-table schema — additive field.
            # {"brand": str, "similarity": float} or None. See brand_phash.py;
            # None whenever no reference_hashes.json is configured.
            "brand_impersonation_match": brand_match,
        },
        "evasion": evasion_rows,
        "headers": headers_rows,
        "downloads": downloads_rows,
        "redirects": redirects_rows,
        "timeline": timeline,
    }

    if load_error:
        result["load_error"] = load_error  # not a schema field — debug aid only
    if blocked_requests:
        # Surfaced rather than silently dropped — an all-zero network
        # section could otherwise look like "clean, inactive page"
        # instead of "we blocked everything this page tried to fetch."
        result["ssrf_blocked_requests"] = blocked_requests
    if credential_probe_result is not None:
        result["credential_probe"] = credential_probe_result
    if qr_linked_scan is not None:
        result["qr_linked_scan"] = qr_linked_scan

    return result


# ---------------------------------------------------------------------------
# Helper detectors
# ---------------------------------------------------------------------------

def detect_qr(screenshot_path):
    """
    HEURISTIC: pyzbar + OpenCV scan of the full-page screenshot.
    Returns (found: bool, urls: list[str]) — `urls` holds any decoded QR
    payload that looks like an http(s) URL, for the recursive
    detonation in scan_url(). Non-URL QR payloads (plain text, vCards,
    wifi configs, etc.) are reported in `found` but not added to `urls`.
    """
    try:
        img = cv2.imread(screenshot_path)
        if img is None:
            return None, []
        decoded = pyzbar.decode(img)
        urls = []
        for d in decoded:
            try:
                payload = d.data.decode("utf-8", errors="ignore")
            except Exception:
                continue
            if payload.lower().startswith(("http://", "https://")):
                urls.append(payload)
        return len(decoded) > 0, urls
    except Exception as e:
        logger.debug("detect_qr failed: %s", e)
        return None, []


async def check_cloaking(browser, url, viewport, allow_private_targets=False, egress_proxy_port=None):
    """
    HEURISTIC: render once as a normal browser UA and once as a bot UA
    (Googlebot string), then diff the visible text. A large divergence is
    a classic cloaking signal. Re-applies the SSRF guard since this
    navigates independently of the main scan — and, like the main scan,
    routes through the egress proxy when one's running, since these
    contexts don't otherwise inherit that protection from the main
    scan's context (Playwright's `proxy` setting is per-context, not
    per-browser).

    COMPARISON METHOD: word-token Jaccard similarity, not raw character
    sequence matching. Two independent page loads of the SAME URL can
    legitimately differ even under the SAME user agent (rotating
    featured-content widgets, cache variance across edge nodes, A/B
    tests) -- confirmed as a real false-positive source (reported on
    wikipedia.org). Token-set comparison is robust to reordering and
    minor structural changes while staying sensitive to genuinely
    different content (a real login-harvest page vs. a blocked/blank
    page still has almost no word overlap).

    MINIMUM-LENGTH GUARD: if either render's visible text is too short
    to compare meaningfully (a block page, an error page, or a page
    that mostly failed to render), this returns None (undetermined)
    rather than risking a confident-looking False/True built on noise.

    Uses wait_until="load" (not "networkidle") for both navigations —
    this check only needs the page's own rendered text, not for every
    ad/tracking/analytics request to go quiet. Tracking-heavy sites
    routinely send background requests indefinitely, which made
    "networkidle" hit its full 20s timeout on both navigations for a
    large fraction of real sites — up to 40s of pure overhead added to
    every single scan for a check that doesn't need it.

    Takes the SAME browser instance the main scan is using (shared or
    pooled) and opens two new isolated contexts on it, rather than
    launching a third standalone Chromium process just for this check.

    Still a HEURISTIC — the similarity threshold below is a starting
    point, not validated against a real labeled dataset. Recalibrate
    before trusting this in production.
    """
    if not await is_target_allowed(url, allow_private_targets):
        logger.warning("check_cloaking: target no longer allowed (%s)", url)
        return None
    proxy_kwarg = {"proxy": {"server": f"http://127.0.0.1:{egress_proxy_port}"}} if egress_proxy_port else {}

    normal_ctx = None
    bot_ctx = None
    try:
        # Each context is created and closed within its OWN try/finally,
        # not just at the end of a shared try block — a goto()/
        # inner_text() timeout on the FIRST navigation (a real, frequent
        # occurrence on slow/ad-heavy sites) used to leave that context
        # open forever, since the previous code only closed it on the
        # line immediately after a successful call. Confirmed as a real
        # leak: an exception on either navigation skipped the
        # corresponding close() with no cleanup path at all.
        try:
            normal_ctx = await browser.new_context(viewport={"width": viewport[0], "height": viewport[1]}, **proxy_kwarg)
            normal_page = await normal_ctx.new_page()
            await normal_page.goto(url, wait_until="load", timeout=20000)
            normal_text = await normal_page.inner_text("body")
        finally:
            if normal_ctx:
                await normal_ctx.close()

        try:
            bot_ctx = await browser.new_context(user_agent=USER_AGENT_BOT,
                                                 viewport={"width": viewport[0], "height": viewport[1]},
                                                 **proxy_kwarg)
            bot_page = await bot_ctx.new_page()
            await bot_page.goto(url, wait_until="load", timeout=20000)
            bot_text = await bot_page.inner_text("body")
        finally:
            if bot_ctx:
                await bot_ctx.close()

        MIN_COMPARABLE_LENGTH = 200
        if len(normal_text) < MIN_COMPARABLE_LENGTH or len(bot_text) < MIN_COMPARABLE_LENGTH:
            logger.debug(
                "check_cloaking: insufficient content to compare (normal=%d chars, bot=%d chars), "
                "returning undetermined rather than risking a false positive",
                len(normal_text), len(bot_text),
            )
            return None

        normal_tokens = set(re.findall(r"\w+", normal_text.lower()))
        bot_tokens = set(re.findall(r"\w+", bot_text.lower()))
        if not normal_tokens or not bot_tokens:
            return None

        intersection = normal_tokens & bot_tokens
        union = normal_tokens | bot_tokens
        similarity = len(intersection) / len(union) if union else 0.0

        # More conservative than a naive midpoint threshold, specifically
        # to reduce false positives on sites with legitimate UA-based or
        # time-based content variance.
        return similarity < 0.4
    except Exception as e:
        logger.warning("check_cloaking failed: %s", e, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _atomic_write_json(path, data):
    """
    Write JSON to `path` atomically: write to a temp file in the same
    directory, then os.rename() over the final path. os.rename is
    atomic on POSIX (same filesystem) — a process watching the target
    directory (e.g. a downstream container's file watcher on a shared
    Docker volume) will only ever see the file appear complete, never
    partially written. Writing directly to the final path and letting a
    watcher race the write is the actual bug this avoids.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, default=str)
        os.rename(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Phishing sandbox scanner (headless Playwright) — "
                     "opens a URL, takes screenshots, extracts telemetry, prints JSON."
    )
    parser.add_argument("url", help="URL to scan, e.g. https://example.com")
    parser.add_argument("--out", default=None,
                         help="Write JSON result to this exact file (atomic write).")
    parser.add_argument("--output-dir", default=None,
                         help="Write JSON result AND screenshots into this directory "
                              "instead of /tmp, using scan_id-based filenames "
                              "(scan_<id>.json, scan_<id>_home.png, scan_<id>_full.png). "
                              "Intended for the shared-Docker-volume pattern — point this "
                              "at the same volume a downstream container watches. Writes "
                              "are atomic (temp file + rename) so a file-watcher on the "
                              "other end never sees a partial write.")
    parser.add_argument("--timeout", type=int, default=45000, help="Navigation timeout in ms")
    parser.add_argument("--request-id", default=None,
                         help="Originating job/request ID to stamp on the scans row.")
    parser.add_argument("--challenge-wait", type=int, default=10,
                         help="Max seconds to wait for a bot-challenge page to self-clear. "
                              "No human/VNC exists in this container — this only catches "
                              "lightweight gates that resolve on their own.")
    parser.add_argument("--proxy", default=None,
                         help="Proxy URL, e.g. http://user:pass@host:port")
    parser.add_argument("--no-human-sim", action="store_true",
                         help="Disable the mouse/scroll human-behavior simulation.")
    parser.add_argument("--probe-credentials", action="store_true",
                         help="OFF by default. Submit a decoy credential and check for "
                              "a post-submit domain change. Only use on targets already "
                              "flagged suspicious upstream.")
    parser.add_argument("--allow-private-targets", action="store_true",
                         help="Bypass the SSRF guard. Local testing only — never use "
                              "this against untrusted input in production.")
    args = parser.parse_args()

    result = asyncio.run(_run_cli_scan(args))

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        scan_id = result["scans"]["scan_id"]

        # Screenshots were already written to /tmp inside scan_url() —
        # move them into the shared output dir under the same
        # scan_id-based naming so the JSON's path fields and the actual
        # files agree, then rewrite those two path fields to match.
        for key, suffix in (("homepage_screenshot_path", "_home.png"),
                             ("fullpage_screenshot_path", "_full.png")):
            src = result.get("screenshots", {}).get(key)
            if src and os.path.exists(src):
                dst = os.path.join(args.output_dir, f"scan_{scan_id}{suffix}")
                shutil.move(src, dst)
                result["screenshots"][key] = dst

        json_path = os.path.join(args.output_dir, f"scan_{scan_id}.json")
        _atomic_write_json(json_path, result)
        print(f"Wrote result to {json_path}")
    elif args.out:
        _atomic_write_json(args.out, result)
        print(f"Wrote result to {args.out}")
    else:
        print(json.dumps(result, indent=2, default=str))


async def _run_cli_scan(args):
    """
    Starts this container's own internal egress proxy before scanning.

    This CLI is now the ONLY entrypoint into the sandbox container — the
    FastAPI service that used to own starting an egress proxy (see
    handoff_reference/app.py's `lifespan`) is no longer part of this
    image. Without starting one here, scan_url() would fall back to
    Chromium's own direct DNS resolution for every scan, which has two
    real, confirmed gaps: the DNS-rebinding TOCTOU window (see
    ssrf_guard.py's docstring), and — more seriously — WebSocket
    connections are completely invisible to the context.route() SSRF
    recheck (confirmed directly: a malicious page's `new WebSocket(...)`
    call to a private target succeeds with zero interaction from the
    route handler at all). Routing through egress_proxy.py closes both,
    verified directly: the same WebSocket connection attempt, made
    through the proxy, gets correctly intercepted and blocked before it
    ever reaches the private target.

    Uses port=0 (OS picks a free ephemeral port) rather than a fixed
    port, since multiple containers could run on the same host/network
    namespace in some deployment shapes, and there's no reason for this
    fully-internal proxy to claim a specific port number.
    """
    if args.allow_private_targets:
        # Explicit opt-out for local testing against a deliberately
        # internal fixture — starting a proxy that would immediately
        # block the very target you're testing against defeats the
        # point of this flag.
        return await scan_url(
            args.url,
            timeout_ms=args.timeout,
            request_id=args.request_id,
            challenge_wait_seconds=args.challenge_wait,
            proxy=args.proxy,
            simulate_human=not args.no_human_sim,
            probe_credentials=args.probe_credentials,
            allow_private_targets=True,
        )

    egress_server = await start_egress_proxy(port=0)
    egress_port = egress_server.sockets[0].getsockname()[1]
    try:
        return await scan_url(
            args.url,
            timeout_ms=args.timeout,
            request_id=args.request_id,
            challenge_wait_seconds=args.challenge_wait,
            proxy=args.proxy,
            egress_proxy_port=egress_port if not args.proxy else None,
            simulate_human=not args.no_human_sim,
            probe_credentials=args.probe_credentials,
            allow_private_targets=False,
        )
    finally:
        egress_server.close()
        await egress_server.wait_closed()


if __name__ == "__main__":
    main()