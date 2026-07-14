# Phishing Sandbox — Pipeline Alignment & Stage 1-4 Integration Notes

This document maps this repo against the 5-stage pipeline architecture
(CyberIntel -> Visual/OCR/DOM -> LightGBM Fusion -> Credential Protection ->
Sandbox Detonation) and explains what's built, what's a stand-in, and
where Stage 1-4 work plugs in once other teams build it.

**Scope note**: this repo builds Stage 5 only -- a single-purpose Docker
container that scans one URL and writes JSON. Everything upstream of
that (the browser extension, the API gateway, the Celery/Redis queue,
file-upload input parsing, verdict fusion, credential-protection
overlays) is explicitly out of scope for this container. Real, tested
starting-point code for those pieces lives in `handoff_reference/` --
this document notes where each Stage 1-4 concern would plug into
*that* code, not into the sandbox container itself, since none of it
belongs inside a container whose only job is detonation.

---

## 1. What this repo actually is

```
Stage 1          Stage 2              Stage 3        Stage 4         Stage 5
CyberIntel   Visual+OCR+DOM    LightGBM Fusion   Cred. Protection  Sandbox Detonation
   XX               XX                  XX              XX               OK
                                                                   (this repo,
                                                                    fully built)
```

Stages 1-4 are not built anywhere in this repo. `handoff_reference/`
has working *stand-ins* for pieces of Stage 1 (URL-shape heuristics)
and Stage 3 (a hand-weighted verdict scorer) -- clearly marked as
heuristics, not the real CyberIntel feeds or a trained model -- plus
starting-point code for the orchestration layer that would eventually
call into Stages 1-4 for real. None of that runs inside the Sandbox
Docker image.

---

## 2. Pipeline mapping

| Diagram node | Status | Where |
|---|---|---|
| User Clicks URL / Manual / Email / File input | Not this repo's job | Backend Team's API layer decides how a URL reaches the sandbox -- see `DOCKER_ARCHITECTURE_IDEATION.md` |
| Local Cache Hit? | Not this repo's job | A cache-before-detonation decision belongs to whatever queues jobs for this container, not the container itself |
| Stage 1: CyberIntel | Stand-in only, in `handoff_reference/` | `quick_heuristics.py`'s `quick_heuristic_score()` -- URL string checks + one RDAP domain-age lookup. No Safe Browsing, OTX, PhishTank, URLhaus, ThreatFox, VirusTotal, crt.sh, or typosquat engine |
| Stage 2: Visual + OCR + DOM (fast pre-filter) | Not built anywhere | See section 3 -- this is a different, cheaper capture than what Stage 5 does |
| Stage 3: Risk Fusion Engine (LightGBM) | Stand-in only, in `handoff_reference/` | `quick_heuristics.py`'s `compute_verdict_from_scan()` -- hand-weighted point system, not a trained classifier |
| Stage 4: Credential Protection | Not built at all | Extension-side UI concern (warn before submitting credentials on a flagged page) -- not applicable now that there's no extension in this repo |
| Sandbox Trigger? | Not this repo's job | Whatever calls this container has already decided to scan; the container doesn't make that decision itself |
| **Stage 5: Sandbox Detonation** | **Fully built** | `backend/phishing_sandbox_scan.py` |
| Final Risk Score + Verdict | Stand-in only, in `handoff_reference/` | `compute_verdict_from_scan()`'s output -- not produced by the sandbox container itself, which only emits raw telemetry |
| SOC Dashboard / Live Forensics | Not built | No dashboard exists anywhere. The sandbox's JSON output (including the `timeline` field) and screenshots are what one would be built against |

---

## 3. The Stage 2 gap, specifically

This is worth its own section because it's easy to misread. Stage 5
(this repo) produces DOM analysis, screenshots, and form-field data --
but that happens *after* a full detonation (stealth, Bezier mouse
movement, SSRF-guarded egress, up to 45 seconds). The pipeline's Stage
2 wants something much cheaper (`<5s` in the original latency budget) --
a quick screenshot + DOM check that runs *before* anything decides
whether Stage 5 is even warranted.

These are not interchangeable, and building real Stage 2 means a
separate, lightweight capture path -- a single quick screenshot, no
stealth, no CDP instrumentation, no credential probing -- feeding
mobileCLIP + Tesseract OCR + a basic DOM check. Nothing in this repo
attempts that; it's a distinct, smaller piece of work for whoever owns
Stage 2.

`backend/brand_phash.py` is in the same spirit as mobileCLIP (visual
brand-similarity matching) but far weaker -- perceptual hashing catches
near-pixel-identical clones, not the broader "looks similar" matching a
real vision model does. It runs *inside* Stage 5 (on the detonation
screenshot), not as a Stage 2 pre-filter.

---

## 4. What to bring from Stage 1-4, and where it plugs in

None of this plugs into the Sandbox container itself -- it plugs into
`handoff_reference/`'s code, or into whatever Backend Team builds from
scratch using that as a starting point.

### Stage 1 -- CyberIntel

**Build:** a function returning a normalized 0-100 score, covering
Google Safe Browsing, AlienVault OTX, PhishTank, URLhaus, ThreatFox,
VirusTotal, crt.sh, a typosquat engine, and InternetDB.

**Plug in:** `handoff_reference/quick_heuristics.py`'s
`quick_heuristic_score()` is the current stand-in; whatever Backend
Team builds should either replace it or run alongside it (the URL-shape
checks still catch things threat-intel feeds haven't indexed yet, like
a domain registered an hour ago).

### Stage 2 -- Visual + OCR + DOM (the fast pre-filter)

**Build:** a new, separate, lightweight function -- not a modification
of `scan_url()`. Something like a single fast screenshot + DOM query,
feeding mobileCLIP + Tesseract OCR + a basic form/login check, with a
`<5s` budget.

**Plug in:** wherever Backend Team's pre-detonation triage logic lives
(the natural home is alongside `quick_heuristic_score()` in
`handoff_reference/quick_heuristics.py`, or its replacement).

### Stage 3 -- LightGBM Fusion

**Build:** a trained classifier using features from Stage 1 + Stage 2 +
(for URLs that get detonated) Stage 5. The Stage 5 feature names are
already fully specified -- they're exactly the field names in
`scan_url()`'s result dict (`phishing_signals.cloaking_detected`,
`form_metrics.password_field_count`, `evasion[].evasion_technique_flags`,
`phishing_signals.js_obfuscation_score`, etc. -- full list in
`phishing_sandbox_scan.py`'s top docstring).

**Plug in:** replace `handoff_reference/quick_heuristics.py`'s
`compute_verdict_from_scan()` with a real model call. Keep the hand-
weighted version around as a fallback for when the trained model isn't
loaded (dev/test environments).

### Stage 4 -- Credential Protection

This is a browser-extension content-script concern (warn before
submitting credentials on a page flagged "caution" rather than
"block"). Since there's no extension in this repo anymore, this is
entirely Frontend/Backend Team's to design from scratch, whenever they
decide what the user-facing surface looks like. The Stage 5 signal that
would gate this decision already exists:
`form_metrics.password_field_count > 0` combined with a "caution"-tier
verdict is the natural trigger condition.

---

## 5. Component reference -- what's in this repo and why

**`backend/phishing_sandbox_scan.py`** -- the Stage 5 detonation engine
and CLI entrypoint. Produces the full result (`scans`, `pages`,
`screenshots`, `network_activity`, `browser_events`, `tls_connection`,
`form_metrics`, `dom_content`, `phishing_signals`, plus list-tables
`evasion`, `headers`, `downloads`, `redirects`). Also handles: the SSRF
guard, session handoff (`storage_state`), human-behavior simulation,
real stealth (`playwright-stealth`), the opt-in credential-redirect
honeytoken probe, bounded recursive QR detonation, and
brand-impersonation pHash matching. Headless-only -- no VNC, no human in
the loop; a detected-but-unresolved bot-challenge is reported via
`phishing_signals.unresolved_interactivity` for whatever consumes the
output to act on.

**`backend/ssrf_guard.py` / `backend/egress_proxy.py`** -- the security
layer. See `README.md`'s "Security model" section.

**`backend/brand_phash.py` + `build_reference_set.py`** -- the
brand-impersonation engine. Ships with no reference images or hashes
(those would be screenshots of real brands' login pages, not
redistributable) -- run `build_reference_set.py` yourself against
screenshots you have the rights to use.

**`handoff_reference/`** -- everything that used to be Backend Team's
API/orchestration layer built inside this repo before scope was
corrected. See its own README for what's there and why it's kept
around despite not being part of the Docker image.

---

## 6. Honest limitations, restated

Everything in this repo is Stage 5 only. `compute_verdict_from_scan`
and `quick_heuristic_score` (both in `handoff_reference/`, not in the
container) are heuristic stand-ins that will both miss real phishing
and flag legitimate sites -- they were tuned for "doesn't fire
constantly during a demo," not accuracy. The credential-redirect probe,
cloaking check, and QR/brand matching are all first-pass heuristics
with explicit `HEURISTIC:` markers in the source -- read those
docstrings before trusting any of their output in a real triage
decision.
