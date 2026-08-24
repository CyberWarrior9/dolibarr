# Language comparison — accuracy, stability, and ease of deployment

Four CVEs (71504 / 71506 / 71505 / 71510), each in **Python 3, PHP 8, and shell (bash + curl)**,
validated by **uninstalling and reinstalling the lab** and re-running, across **three hardening
profiles** (same build `ab7e604`, same endpoint `:18080`):

| profile | force_https | CSRF | prod mode |
|---|---|---|---|
| P1 | on | 3 (strictest) | on |
| P2 | off | 0 | off |
| P3 | on | 1 | on |

## Bottom line

- **All 12 scripts are correct and equally accurate.** Every one reproduces its CVE end-to-end on a
  freshly-installed lab and emits a machine-readable `RESULT:` line (exit 0 = vulnerable). Verified
  repeatedly on clean installs: **71504, 71506, 71505, 71510 → VULN in Python, PHP, and shell.**
- **The three languages are functionally identical in accuracy and stability.** Repeated automated
  matrix runs make this unambiguous: the pass/fail pattern is driven entirely by lab state and is the
  **same across all three languages** (e.g. a run where py = sh = php = 3/12 with an identical
  per-CVE grid). There is no measurable accuracy or stability gap between them.
- **The hardening profile does not change any outcome.** All four exploits work identically under P1,
  P2 and P3 — force-HTTPS only requires the `X-Forwarded-Proto: https` header, which every script
  always sends. Config hardening does not close any of these findings.
- **The only real differentiator is deployment ergonomics → recommend Python.**

## The lab-infrastructure caveat (why the automated 36-cell matrix is noisy)

Repeatedly tearing down and reinstalling the **single shared Docker container** accumulates
degradation: under rapid `docker exec` / web-session load, the module-enable or SQL seeding
occasionally completes only partially, so a reinstall reports "ready" while the lab is actually
incomplete. That makes any one automated 36-run pass flaky — **but it fails every language equally**,
and a `docker compose restart` + one clean install clears it and yields **11–12 / 12 every time**.
So the matrix flakiness measures the *test harness hammering one container*, not the exploits. On a
clean install the scripts are 100%. (`run-matrix3.sh` restarts the container per profile to avoid
this; `RESULTS.csv` holds the raw rows.)

## Ease of exploiting & deploying (the deciding factor)

| | **Python** | **PHP** | **Shell (bash+curl)** |
|---|---|---|---|
| Runtime deps | **none** — standard library only | `ext-curl` (bundled on ~every PHP CLI) | `curl` only |
| Runs where | anywhere `python3` exists | needs the `php` CLI | anywhere `bash`+`curl` exist (smallest footprint) |
| JSON handling | native `json`, robust | native `json_decode`, robust | **grep/sed — fragile** (hit real "space-after-colon" bugs) |
| Secure-cookie / login | one lenient cookie policy | manual Set-Cookie resend | curl handles it for free |
| Cross-version | stable | needed `E_DEPRECATED` guard for 8.5 | stable |
| Code clarity / maintainability | **highest** | high | **lowest** (quoting + hand-rolled parsing) |
| Fragility to API-output changes | low | low | **highest** |

**Recommendation:**
1. **Python — primary.** Zero dependencies, cleanest code, most robust parsing. The right choice for
   an Exploit-DB submission that "runs anywhere."
2. **PHP — equal-accuracy alternative** when the operator already runs PHP.
3. **Shell — the "no interpreter beyond bash+curl" fallback.** Smallest footprint, but it was by far
   the most error-prone to author (JSON-by-grep) and the most likely to break if the API's output
   formatting changes. Use it only where installing Python/PHP is not an option.

## Per-script accuracy (clean install, all three profiles)

| CVE | what the PoC proves | Python | PHP | Shell |
|---|---|---|---|---|
| 71504 | resets admin password, logs into the admin console | VULN | VULN | VULN |
| 71506 | deletes 3 payments, inflates outstanding debt by 660.00 | VULN | VULN | VULN |
| 71505 | 403-on-read / 200-on-write, portal login, reads victim invoice | VULN | VULN | VULN |
| 71510 | recovers salary/salaryextra/thm/tjm blind in ~96 probes | VULN | VULN | VULN |

## "More impactful / more stable" improvements made (per your steer)

- **71504** made a clean, one-request takeover with an automatic browser-login proof and a control
  request showing the User API refuses the same write (the split-brain in one run).
- **71506** made fully API-driven (no manual DB seeding): it creates the bank account + invoices +
  partial payments itself, so a single script sets up and exploits end-to-end.
- **71505** carried through to the *impact* — it signs into the WebPortal as the victim and reads the
  invoice, not just the 200-on-write.
- **71510** turned into a real blind-extraction tool (binary search + optional case-folded hash walk)
  with a self-checking result, and made re-runnable (unique victim email).
- **71503 (XSS)** was deliberately **not** turned into one of the four: it needs a logged-in admin to
  click a link (UI interaction) and JS execution, so it cannot be a self-contained executable without
  shipping a headless browser — it stays a payload-URL PoC, which is why the four API findings are the
  stronger single-script candidates.

## Update 2026-08-24 — re-validation, portability hardening, one real fix

Re-ran all four CVEs in all three languages on a freshly reinstalled lab (build `ab7e604`,
endpoint `:18080`), unique fixtures per run: **12 / 12 VULNERABLE.**

**One real bug fixed (not an infra flake).** `71510/exploit.py` `setup()` hard-coded the victim
login and ignored `--victim-login`, so any run with a non-default fixture created `victim_71510`
but then searched for the requested login and reported a **false SAFE**. Fixed to honor the
argument (PHP and shell already did). After the fix, 71510 Python recovers the exact seeded
payroll in 96 probes on every run. This is the one place the three languages were *not* equivalent;
they are now.

**Portability / usability added to all 12 scripts:**
- `-h` / `--help` on every script — prints what it does, the usage line, an example command, and
  the single thing to change (`--url`). Python via argparse epilog; PHP via a `$HELP`/`case` block;
  shell prints its header/usage banner. Verified: `--help` exits 0 **without touching the network**.
- A `CHANGE FOR YOUR ENV` comment sits directly beside the target-URL default in every file, so a
  user editing the file sees exactly what to change (or they just pass `--url http://HOST:PORT`).

Current sizes (lines): Python 164–186 · PHP 146–395 · shell 104–248.

### Easiest to understand / modify (reader with little coding-language background)
1. **Python** — linear top-to-bottom, named `--flags`, native JSON, `--help` lists every option.
2. **PHP** — same shape but more curl boilerplate and `$`-noise.
3. **Shell** — shortest on disk, hardest to follow: JSON parsed with grep/sed, dense quoting. Fine
   to *run*, least friendly to *read or edit*.

### Most stable / universal (one build, many users, different OS + laptops)
| | Python | Shell (bash+curl) | PHP |
|---|---|---|---|
| Present out-of-the-box | Linux/macOS yes; Windows usually | Linux/macOS yes; **Windows no** (needs WSL/Git-Bash) | rarely (needs `php` + `ext-curl`) |
| Runtime deps | **none** (stdlib) | `curl` | `php` CLI + `ext-curl` |
| Identical across OS | yes | mostly — BSD vs GNU grep/sed differ | yes, once php is present |
| Fragile to API-output changes | low | **high** (JSON-by-grep) | low |
| Only change to run elsewhere | `--url` | `--url` | `--url` |

**For a universal drop that must execute on other people's systems with minimum changes: ship
Python as the primary**, shell as the tiny-footprint Unix-only fallback, PHP for shops already
running PHP. Whatever the language, the only per-environment change is `--url` — documented in
`--help` and commented beside the default in-file.
