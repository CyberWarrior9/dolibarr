# Dolibarr ERP/CRM — end-to-end exploit pack (CVE-2026-71504 / 71505 / 71506 / 71510)

Self-contained proof-of-concept exploits for four vulnerabilities in **Dolibarr ERP/CRM**,
each provided in **Python 3 and shell (bash + curl)**. Every script provisions its own
victim data, runs the exploit from a low-privilege position, verifies the impact over HTTP, and
prints a machine-readable `RESULT:` line (exit `0` = vulnerable, `2` = not vulnerable, `1` = error).

> Authorized security testing against an **isolated lab** only. These scripts change state
> (reset an administrator password, delete payments, reset a portal password). Do not run them
> against systems you do not own or are not explicitly authorized to test.

| CVE | Class (CWE) | CVSS | One line |
|---|---|---|---|
| **CVE-2026-71504** | Mass assignment (CWE-915/620) | 8.3 | A membership-desk API key resets the administrator's password and logs in. |
| **CVE-2026-71505** | BOLA / IDOR (CWE-639) | 8.1 | A `societe.creer` key resets an unreadable company's portal password, signs in, reads its invoices. |
| **CVE-2026-71506** | Incorrect authorization (CWE-863) | 6.5 | A "Delete invoices" key hard-deletes recorded customer payments (phantom debt). |
| **CVE-2026-71510** | Incorrect authorization (CWE-863/200) | 6.5 | A "list users" key reads hidden salaries + a password-hash image through a `sqlfilters` boolean oracle. |

**Affected:** Dolibarr `<= 25.0.0-alpha` (develop, commit `ab7e60406d`). **Fixed in 24.0.0.**
CVE-2026-71506 is additionally present in released **23.0.3**. CVEs assigned via VulnCheck (CNA).

## Prerequisite: a low-privilege API key

Each exploit acts from an ordinary Dolibarr REST API key holding a **routine** right:

| CVE | Attacker right(s) |
|---|---|
| 71504 | `adherent.lire` + `adherent.creer` (membership desk) |
| 71505 | `societe.lire` + `societe.creer` (can create companies) |
| 71506 | `facture.lire` + `facture.supprimer` (can delete invoices) |
| 71510 | `user.user.lire` (can list users) |

On a real engagement you already hold such a key. Dolibarr will **not** let even an admin set a
user's `api_key` over the REST API (405), so the lab seeds these keys directly — see
`_lab/reinstall.sh`. Fixture creation (the victim member/company/invoice/user) is done by the
`--setup` phase using an admin key and is clearly separated from the vulnerability itself; pass
`--no-setup` on a real target where the data already exists.

## Usage

```
python3 <cve-dir>/exploit.py            # zero dependencies (standard library only)
bash     <cve-dir>/exploit.sh           # bash + curl only, no jq

  --url URL            target base URL         (default http://127.0.0.1:18080)
  --key KEY            attacker API key        (default the lab-seeded att-715NN-key)
  --admin-key KEY      admin key for --setup   (default admin-audit-key-2026)
  --no-setup           skip fixture creation (real target)
  --json               emit a single JSON result object
```

## Lab

`_lab/reinstall.sh <https 0|1> <csrf 0|1|3> <prod 0|1>` rebuilds a clean Dolibarr
`25.0.0-alpha @ ab7e604` on `:18080` with the required modules, the admin key, and the four
attacker keys. `_lab/run-matrix.sh` rebuilds under three hardening profiles and runs all eight
scripts, scoring accuracy and stability per language.

Author: **CodeAnt AI Security Research** &lt;securityresearch@codeant.ai&gt;
