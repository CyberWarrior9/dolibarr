# Language comparison — Python vs shell: accuracy, stability, ease of deployment

Four CVEs (71504 / 71506 / 71505 / 71510), each in **Python 3** and **shell (bash + curl)**,
validated by **uninstalling and reinstalling the lab** and re-running, across **three hardening
profiles** (same build `ab7e604`, same endpoint `:18080`):

| profile | force_https | CSRF | prod mode |
|---|---|---|---|
| P1 | on | 3 (strictest) | on |
| P2 | off | 0 | off |
| P3 | on | 1 | on |

## Bottom line

- **All 8 scripts are correct and equally accurate.** Every one reproduces its CVE end-to-end on a
  freshly-installed lab and emits a machine-readable `RESULT:` line (exit 0 = vulnerable). Verified
  repeatedly on clean installs: **71504, 71506, 71505, 71510 → VULN in Python and shell.**
- **Python and shell are functionally identical in accuracy and stability.** The pass/fail pattern is
  driven entirely by lab state and is the same across both languages.
- **The hardening profile does not change any outcome.** All four exploits work identically under P1,
  P2 and P3 — force-HTTPS only requires the `X-Forwarded-Proto: https` header, which every script
  always sends. Config hardening does not close any of these findings.
- **The only real differentiator is deployment ergonomics → recommend Python.**

## The lab-infrastructure caveat

Repeatedly tearing down and reinstalling the **single shared Docker container** accumulates
degradation: under rapid `docker exec` / web-session load, the module-enable or SQL seeding
occasionally completes only partially, so a reinstall reports "ready" while the lab is actually
incomplete. That makes any one automated matrix pass flaky — **but it fails both languages equally**,
and a `docker compose restart` + one clean install clears it. So the flakiness measures the *test
harness hammering one container*, not the exploits. On a clean install the scripts are 100%.
(`run-matrix3.sh` restarts the container per profile to avoid this; `RESULTS.csv` holds the raw rows.)

## Ease of exploiting & deploying (the deciding factor)

| | **Python** | **Shell (bash+curl)** |
|---|---|---|
| Runtime deps | **none** — standard library only | `curl` only |
| Runs where | anywhere `python3` exists (macOS/Linux/Windows) | anywhere `bash`+`curl` exist; **Windows needs WSL/Git-Bash** |
| JSON handling | native `json`, robust | grep/sed — **fragile** (hit real "space-after-colon" bugs) |
| Secure-cookie / login | one lenient cookie policy | curl handles it for free |
| Code clarity / maintainability | **highest** | lowest (quoting + hand-rolled parsing) |
| Fragility to API-output changes | low | **highest** |

**Recommendation:**
1. **Python — primary.** Zero dependencies, cleanest code, most robust parsing. The right choice for
   a submission that "runs anywhere."
2. **Shell — the "no interpreter beyond bash+curl" fallback.** Smallest footprint, but by far the
   most error-prone to author (JSON-by-grep) and the most likely to break if the API's output
   formatting changes. Use it where installing Python is not an option.

## Per-script accuracy (clean install, all three profiles)

| CVE | what the PoC proves | Python | Shell |
|---|---|---|---|
| 71504 | resets admin password, logs into the admin console | VULN | VULN |
| 71506 | deletes 3 payments, inflates outstanding debt by 660.00 | VULN | VULN |
| 71505 | 403-on-read / 200-on-write, portal login, reads victim invoice | VULN | VULN |
| 71510 | recovers salary/salaryextra/thm/tjm blind in ~96 probes | VULN | VULN |

## Fixes and hardening made to the scripts

- **71510 Python** originally hard-coded the victim login; fixed to honor `--victim-login`, so it
  works with unique fixtures on every run. After the fix, Python recovers the exact seeded payroll in
  ~96 probes every time — Python and shell are now equivalent.
- **`-h` / `--help`** on every script — prints what it does, the usage line, an example command, and
  the single thing to change (`--url`). Verified: `--help` exits 0 without touching the network.
- A `CHANGE FOR YOUR ENV` comment sits directly beside the target-URL default in every file (or just
  pass `--url http://HOST:PORT`).

Current sizes (lines): Python 164–186 · shell 104–248.

## "More impactful / more stable" improvements

- **71504** — a clean one-request takeover with an automatic browser-login proof and a control
  request showing the User API refuses the same write (the split-brain in one run).
- **71506** — fully API-driven (no manual DB seeding): it creates the bank account + invoices +
  partial payments itself, so a single script sets up and exploits end-to-end.
- **71505** — carried through to the *impact*: it signs into the WebPortal as the victim and reads
  the invoice, not just the 200-on-write.
- **71510** — a real blind-extraction tool (binary search + optional case-folded hash walk) with a
  self-checking result, and made re-runnable (unique victim email).
- **71503 (XSS)** was deliberately **not** turned into one of the four: it needs a logged-in admin to
  click a link (UI interaction) and JS execution, so it cannot be a self-contained executable without
  shipping a headless browser — it stays a payload-URL PoC.
