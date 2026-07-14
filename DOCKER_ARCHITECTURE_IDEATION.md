# Docker Architecture — Ideation Plan

How the standalone Sandbox container (this repo) connects to the rest
of the pipeline once Backend Team builds their own Celery/Redis/API
layer, using the same shared-Docker-volume pattern your PDF describes
for Stage 2's screenshot-capture flow.

**Scope reminder**: this document plans the *connection points*. It
does not build Backend Team's Celery worker, Redis queue, or API
gateway — those are explicitly their job. What's built here is the
Sandbox container itself (see `README.md`) plus the two concrete
hooks (`--output-dir`'s atomic writes, and the container's CLI
interface) that make connecting to it straightforward whichever way
Backend Team decides to call it.

---

## 1. The overall shape, adapted from your PDF's Stage 2 pattern

Your PDF's Stage 2 flow is: browser extension → Nginx → Backend
Container (FastAPI) → writes screenshot to a **shared Docker volume** →
queues a Celery job → Celery Worker Container picks the job off Redis →
processes the shared file.

Stage 5 (this sandbox) is a heavier, slower job than Stage 2's
screenshot-and-forward — it doesn't fit behind a request/response HTTP
call the way Stage 2 does (a full detonation can take 10-45+ seconds).
It fits the **same shared-volume, queue-driven shape**, just with the
sandbox itself as the thing that does the heavy work instead of a
Celery worker calling out to mobileCLIP/OCR:

```
                    +-----------------+
  request  -------->|  Nginx           |
                    +--------+---------+
                             v
                    +-----------------+      +----------+
                    | Backend Container|----->|  Redis    |  (queue/broker --
                    | (FastAPI)        |<-----|  (queue)  |   Backend Team owns)
                    +--------+---------+      +----------+
                             | writes job metadata,
                             | reads results back
                             v
                    +----------------------+
                    |   shared_scans volume |<-+
                    +----------+------------+  |
                                |                | atomic writes
                                v                | (scan_<id>.json,
                    +----------------------+    |  scan_<id>_*.png)
                    |  SANDBOX CONTAINER     |---+
                    |  (this repo)           |
                    |  phishing_sandbox_scan |
                    +----------------------+
```

Backend Team's Celery Worker Container is the thing that actually
*triggers* the sandbox container per job (see SS2 for the two ways to
do that) and then reads the result back off the same shared volume.

---

## 2. How Backend Team's worker triggers the sandbox container

Two real options, with honest tradeoffs — this is Backend Team's call,
not something to silently decide for them.

### Option A: spawn a fresh sandbox container per job (recommended)

Backend's Celery worker runs (via the Docker socket, or a Docker API
client library):

```bash
docker run --rm \
  -v shared_scans:/app/output \
  sandbox:latest \
  https://suspicious-url.example --output-dir /app/output
```

...waits for the container to exit, then reads
`shared_scans/scan_<id>.json` (and the two `.png` files) back.

**Pros**: clean isolation — every scan gets a genuinely fresh container,
not just a fresh browser context in a long-lived process. No shared
in-process state between scans at all. Matches the "container per
concern" shape your PDF already uses for Stage 2.

**Cons**: needs the Celery worker to have Docker access (either the
host's Docker socket mounted in, or a remote Docker API endpoint) —
worth naming explicitly, since mounting `/var/run/docker.sock` into a
container is a real privilege-escalation-adjacent pattern (a compromised
worker could use it to control the whole Docker host, not just spawn
sandbox containers). If you go this route, at minimum restrict what the
worker can do with that socket (a scoped Docker API proxy, not a raw
socket mount) rather than treating it as a minor detail.

Also has a real per-job cost: a fresh `docker run` pays Chromium's
process-launch cost every time (no browser pooling across jobs) — a few
seconds of overhead per scan. For a queue-driven async job (not a
user-facing request/response), that's usually an acceptable trade for
the isolation.

### Option B: import the sandbox code directly into the worker image

Backend's own Celery Worker image installs the same dependencies
(`docker/requirements.txt`) and copies `backend/` in, then a Celery
task body just does:

```python
from phishing_sandbox_scan import scan_url
result = await scan_url(url, output_dir="/app/output")  # hypothetical direct call
```

**Pros**: no Docker-in-Docker, no socket-mounting security question at
all. Can reuse a pooled browser across jobs within one worker process
(the performance pattern from the earlier `app.py` prototype in
`handoff_reference/`) instead of paying a fresh launch cost per job.

**Cons**: couples Backend Team's worker image to this repo's exact
Python/Playwright version — every time the sandbox engine updates,
their worker image needs rebuilding too, rather than just pulling a new
`sandbox:latest` tag. Loses the clean container-per-job isolation
boundary.

**Recommendation**: Option A if Backend Team is comfortable operating
Docker-in-Docker safely (a scoped API proxy, not a raw socket mount);
Option B if they'd rather avoid that entirely and are fine with the
tighter coupling. Either way, the sandbox container's actual interface
(SS3) doesn't change — this is purely how it gets invoked.

---

## 3. The sandbox container's interface (already built)

```bash
docker run --rm \
  -v shared_scans:/app/output \
  sandbox:latest \
  <URL> [--output-dir /app/output] [--challenge-wait 10] [--timeout 45000] \
        [--request-id <backend's correlation id>] [--proxy <proxy-url>] \
        [--probe-credentials] [--allow-private-targets]
```

- **Input**: one URL, as a positional CLI argument. No file upload, no
  batch mode, no HTTP API — those are Backend Team's job to build on
  top of this, in whatever shape their own API needs (`handoff_reference/`
  has working starting-point code for a batch/file-upload layer if
  useful, but it's not part of this container).
- **Output**: with `--output-dir`, writes `scan_<scan_id>.json`,
  `scan_<scan_id>_home.png`, and `scan_<scan_id>_full.png` into that
  directory, **atomically** (temp file + `os.rename`) — a file-watcher
  on Backend Team's side (see SS4) will only ever see complete files
  appear, never a partial write mid-scan.
- **`--request-id`**: pass whatever correlation ID your queue job
  already has, so the `scans.request_id` field in the output JSON ties
  back to your own job tracking. If omitted, the container generates
  its own UUID.
- **Exit**: the process exits after writing output. There's no
  persistent service, no port, nothing left running.

---

## 4. Reading results back: file watcher, not polling

Once the sandbox container writes `scan_<id>.json` into the shared
volume, Backend Team's worker needs to know it's ready. Two options,
same shape as the atomic-write guarantee this container already
provides:

- **Simple**: poll for the file's existence every N seconds. Works,
  adds latency up to N seconds per job, fine for a first pass.
- **Better**: use a file-system watcher (e.g. Python's `watchdog`
  library) on the shared volume directory, triggered instantly the
  moment `os.rename()` makes the final file appear. Since the sandbox
  container writes atomically, the watcher is guaranteed to only ever
  see the complete file — no risk of reading a half-written JSON
  payload mid-scan, no need for the watcher to itself re-check "is this
  file actually done."

---

## 5. Concrete example: one full round trip

```bash
# 1. Backend's worker (however it's triggered -- see SS2) runs:
docker run --rm \
  -v shared_scans:/app/output \
  sandbox:latest \
  https://paypal-verify.suspicious-domain.example \
  --output-dir /app/output \
  --request-id "celery-job-8841"

# 2. Sandbox container scans, writes atomically, exits:
#      shared_scans/scan_a1b2c3d4-....json
#      shared_scans/scan_a1b2c3d4-...._home.png
#      shared_scans/scan_a1b2c3d4-...._full.png

# 3. Backend's watcher picks up the new .json file, reads it:
{
  "scans": {"scan_id": "a1b2c3d4-...", "request_id": "celery-job-8841", ...},
  "phishing_signals": {
    "cloaking_detected": false,
    "js_obfuscation_score": 0.847,
    "unresolved_interactivity": false,
    "brand_impersonation_match": {"brand": "paypal", "similarity": 0.94},
    ...
  },
  "form_metrics": {"password_field_count": 1, "cross_domain_form_count": 1, ...},
  ...
}

# 4. Backend Team's own logic (Stage 3 fusion, or the heuristic
#    stand-in in handoff_reference/quick_heuristics.py) turns this into
#    a verdict, persists it (handoff_reference/db_alignment_middleware.py
#    has a tested starting point for that), and reports back to
#    whatever originated the job (celery-job-8841).
```

---

## 6. What this plan deliberately does NOT decide

- Which Celery broker config, task retry policy, or queue naming
  convention Backend Team uses — their call entirely.
- Whether the Nginx/Backend Container split from your PDF's Stage 2
  diagram applies identically to Stage 5, or whether Stage 5 jobs get
  their own dedicated queue/worker pool (likely worth doing, given how
  much heavier a Stage 5 detonation is than a Stage 2 screenshot POST --
  you don't want a Stage 5 backlog blocking Stage 2's much faster jobs
  on the same worker pool).
- Concurrency limits on how many sandbox containers run simultaneously
  -- that's a resource-planning decision for whoever operates the fleet,
  not something baked into the container itself.
