# Dolibarr ERP/CRM — four vulnerabilities (Exploit-DB submission text)

All four were found on **Dolibarr `25.0.0-alpha`** (develop branch, commit `ab7e60406d`) on a
hardened production profile (install lock on, production mode, HTTPS forced, CSRF strictest) and
reproduced end-to-end on an isolated Docker instance. **Fixed in Dolibarr 24.0.0.** CVE-2026-71506
is additionally present in released **23.0.3**. CVEs assigned via VulnCheck (CNA). Each finding
ships a self-contained PoC in `exploit.py` / `exploit.php` / `exploit.sh`.

---

## CVE-2026-71504 — Members REST API mass assignment → administrator takeover

- **Type:** CWE-915 mass assignment + CWE-620 unverified password change · **CVSS 3.1 8.3**
  `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L`
- **Component:** `htdocs/adherents/class/api_members.class.php`, `Members::post()` / `put()`.

`Members::post()`/`put()` authorize only `adherent.creer`, then copy every JSON body key onto the
member object with no allow-list. Two keys are not member data the caller should control: `user_id`
(which linked user account) and `pass` (a new password). They propagate through
`Adherent::setPassword()` with default sync flags, which loads the user named by the attacker and
overwrites its password — with no `user`-management right. A membership-desk key pointed at the
administrator (default `rowid` 1) resets the admin password; the attacker then logs in as admin. The
sibling User API refuses the identical write (`PUT /users/{id}` → 403 "User update not allowed",
`api_users.class.php:429`). **PoC:** `exploit.py` — one `POST /api/index.php/members`, then a browser
login as `admin` proving the admin console renders.

---

## CVE-2026-71505 — Third-party site-account BOLA (IDOR) → customer-portal takeover

- **Type:** CWE-639 authorization bypass through user-controlled key · **CVSS 3.1 8.1**
  `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **Component:** `htdocs/societe/class/api_thirdparties.class.php`, `putSocieteAccount()`
  (route `PUT /thirdparties/{id}/accounts/{site}`).

The write route checks only `societe.creer` and selects the account straight from the caller-supplied
company id, omitting the per-object `_checkAccessToResource('societe', id)` its sibling *read* route
(`getSocieteAccounts()`) performs. A key holding only `societe.lire` + `societe.creer` is refused
(403) when it reads a company, yet succeeds (200) writing a new WebPortal password onto that same
company; the PUT response additionally leaks the pre-update bcrypt verifier and login. The attacker
then signs into `/public/webportal/index.php` **as the victim company** and reads its invoices.
**PoC:** `exploit.py` — 403-on-read / 200-on-write, then a portal login and invoice read.

---

## CVE-2026-71506 — Payment-deletion API gated on the wrong permission

- **Type:** CWE-863 incorrect authorization · **CVSS 3.1 6.5**
  `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` · also present in released **23.0.3**.
- **Component:** `htdocs/compta/facture/class/api_paiements.class.php`, `Paiements::delete()`
  (route `DELETE /paiements/{id}`).

`Paiements::delete()` guards on `facture.supprimer` ("Delete invoices") — the wrong right. Every other
payment-mutation path in the codebase checks the dedicated `facture.paiement` ("Issue payments on
invoices") right, and it performs no object-level check on the invoices the payment touches. So a key
holding only "Read invoices" + "Delete invoices" hard-deletes recorded customer payments. Because an
invoice's paid figure is the sum of its payment rows, each deletion inflates the outstanding balance
(phantom debt). A control key without `facture.*` is correctly refused (403,
`api_paiements.class.php:230`). **PoC:** `exploit.py` — deletes three partial payments (110/220/330 on
1000.00 invoices) and shows the outstanding balance inflate by 660.00.

---

## CVE-2026-71510 — Users REST API `sqlfilters` boolean oracle

- **Type:** CWE-863 incorrect authorization + CWE-200 · **CVSS 3.1 6.5**
  `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` · **disclosure only** (case-folded hash, not a usable credential).
- **Component:** `htdocs/user/class/api_users.class.php`, `Users::index()`, via
  `dolForgeSQLCriteriaCallback()` in `functions.lib.php`.

`GET /users` splices the caller-supplied `sqlfilters` parameter into the WHERE clause after a *syntax*
sanitizer only — no column is ever authorized. A key holding only `user.user.lire` can filter on
columns the serializer refuses to return (`salary`, `salaryextra`, `thm`, `tjm`, `pass_crypted`): a
returned row means the predicate is true, an empty array false. That one bit binary-searches every
hidden numeric value (~24 requests each) and walks a case-folded image of the bcrypt verifier. A
whole-workforce sweep needs no target id, and a nonexistent-column probe leaks the schema via the raw
driver error (HTTP 503). **PoC:** `exploit.py` — recovers exact salaries blind in ~96 requests.
