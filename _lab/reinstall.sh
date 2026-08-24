#!/usr/bin/env bash
# Clean-reinstall the Dolibarr lab to a "ready" state for exploit testing.
# Same build (25.0.0-alpha @ ab7e604) and endpoint (:18080) every time; only the
# hardening profile varies.  Usage: reinstall.sh <https 0|1> <csrf 0|1|3> <prod 0|1>
#
# "Ready" = fresh install + profile applied + required modules on + admin api_key +
# the four low-privilege ATTACKER api_keys seeded (api_key cannot be set over the
# REST API — 405 — so the lab seeds it; on a real target you already hold such a key).
set -uo pipefail
HTTPS="${1:-1}"; CSRF="${2:-3}"; PROD="${3:-1}"
DBPW='DoliAudit-Root-2026!'
WEB=dolibarr-cve-audit-web-1; DBC=dolibarr-cve-audit-db-1
CONF=/private/tmp/dolibarr-cve-audit/repo/htdocs/conf/conf.php
BASE='http://127.0.0.1:18080'; H='X-Forwarded-Proto: https'
ADMINPW='FinalCheck-2026!'; ADMINKEY='admin-audit-key-2026'
dbe(){ docker exec -i "$DBC" sh -c 'exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" dolibarr_audit -e "$1"' _ "$1" 2>/dev/null; }
dbroot(){ docker exec -i "$DBC" sh -c 'exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -e "$1"' _ "$1" 2>/dev/null; }

echo "[lab] profile https=$HTTPS csrf=$CSRF prod=$PROD  — teardown"
docker exec "$WEB" sh -c 'rm -f /var/www/documents/install.lock' 2>/dev/null
dbroot "DROP DATABASE IF EXISTS dolibarr_audit;"
: > "$CONF"
echo "[lab] step1/2/5 (fresh install)"
docker exec "$WEB" sh -c "cd /var/www/html/install && php step1.php set en_US /var/www/html /var/www/documents $BASE root '$DBPW' mysqli db dolibarr_audit root '$DBPW' 3306 llx_ 1 0" >/dev/null 2>&1
docker exec "$WEB" sh -c "cd /var/www/html/install && php step2.php set en_US" >/dev/null 2>&1
docker exec "$WEB" sh -c "cd /var/www/html/install && php step5.php 0.0.0 25.0.0 en_US set admin '$ADMINPW' '$ADMINPW' 1" >/dev/null 2>&1
[ -n "$(dbe 'SELECT rowid FROM llx_user WHERE admin=1 LIMIT 1;')" ] || { echo "[lab] FATAL: admin not created"; exit 1; }
# Create the accounting-bookkeeping tables (present on a normal install; the fast headless
# install omits these module tables, and Paiement::delete touches them when unwinding a
# bank-linked payment).  Lets bank-linked customer payments delete over the API (CVE-71506).
TBL=/var/www/html/install/mysql/tables
for f in llx_accounting_bookkeeping-accounting.sql llx_accounting_bookkeeping-accounting.key.sql llx_accounting_bookkeeping_tmp-accounting.sql llx_accounting_bookkeeping_tmp-accounting.key.sql; do
  docker exec "$WEB" sh -c "cat $TBL/$f" 2>/dev/null | docker exec -i "$DBC" sh -c 'exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" dolibarr_audit' 2>/dev/null
done

echo "[lab] apply profile to conf.php + const"
sed -i '' -e "s/\$dolibarr_main_force_https='[^']*';/\$dolibarr_main_force_https='$HTTPS';/" "$CONF"
if grep -q 'dolibarr_main_prod' "$CONF"; then sed -i '' -e "s/\$dolibarr_main_prod='[^']*';/\$dolibarr_main_prod='$PROD';/" "$CONF"; else printf "\$dolibarr_main_prod='%s';\n" "$PROD" >> "$CONF"; fi
if [ "$CSRF" -gt 0 ]; then dbe "INSERT INTO llx_const (name,entity,value,type,visible) VALUES ('MAIN_SECURITY_CSRF_WITH_TOKEN',1,'$CSRF','chaine',0) ON DUPLICATE KEY UPDATE value='$CSRF';"; else dbe "DELETE FROM llx_const WHERE name='MAIN_SECURITY_CSRF_WITH_TOKEN';"; fi
dbe "UPDATE llx_user SET api_key='$ADMINKEY' WHERE rowid=1;"
# WebPortal runtime config (an operator running the customer portal sets these; not part of any vuln)
dbe "INSERT INTO llx_const (name,entity,value,type,visible) VALUES ('WEBPORTAL_USER_LOGGED',1,'1','chaine',0),('WEBPORTAL_INVOICE_LIST_ACCESS',1,'1','chaine',0) ON DUPLICATE KEY UPDATE value=VALUES(value);"

enable_modules(){  # via admin web session; idempotent
  local JAR t T M; JAR=$(mktemp)
  t=$(curl -s -c "$JAR" -H "$H" "$BASE/index.php" | grep -o 'name="token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
  curl -s -b "$JAR" -c "$JAR" -H "$H" -o /dev/null --data-urlencode "token=$t" --data-urlencode 'actionlogin=login' --data-urlencode 'loginfunction=loginfunction' --data-urlencode "username=admin" --data-urlencode "password=$ADMINPW" "$BASE/index.php?mainmenu=home"
  newtoken(){ curl -s -b "$JAR" -c "$JAR" -H "$H" "$BASE/admin/index.php" | grep -o 'anti-csrf-newtoken" content="[^"]*"' | head -1 | sed 's/.*content="//;s/"//'; }
  for M in modApi modSociete modFacture modAdherent modExpenseReport modSalaries modProduct modBanque modPrelevement modWebPortal; do
    T=$(newtoken); curl -s -b "$JAR" -H "$H" -o /dev/null "$BASE/admin/modules.php?action=set&token=$T&value=$M&mode=common"
  done
  rm -f "$JAR"
}
seed_one(){ # login key
  dbe "DELETE ur FROM llx_user_rights ur JOIN llx_user u ON u.rowid=ur.fk_user WHERE u.login='$1'; DELETE FROM llx_user WHERE login='$1';"
  dbe "INSERT INTO llx_user (entity,login,lastname,firstname,admin,statut,employee,datec,api_key) VALUES (1,'$1','Att','Audit',0,1,1,NOW(),'$2');"
}
seed_attackers(){
  seed_one att_71504 att-71504-key; seed_one att_71506 att-71506-key
  seed_one att_71505 att-71505-key; seed_one att_71510 att-71510-key
  dbe "INSERT IGNORE INTO llx_user_rights (entity,fk_user,fk_id) SELECT 1,u.rowid,r.id FROM llx_user u JOIN llx_rights_def r ON r.module='adherent' AND r.perms IN ('lire','creer') AND (r.subperms IS NULL OR r.subperms='') WHERE u.login='att_71504';"
  dbe "INSERT IGNORE INTO llx_user_rights (entity,fk_user,fk_id) SELECT 1,u.rowid,r.id FROM llx_user u JOIN llx_rights_def r ON r.module='facture' AND r.perms IN ('lire','supprimer') AND (r.subperms IS NULL OR r.subperms='') WHERE u.login='att_71506';"
  dbe "INSERT IGNORE INTO llx_user_rights (entity,fk_user,fk_id) SELECT 1,u.rowid,r.id FROM llx_user u JOIN llx_rights_def r ON r.module='societe' AND r.perms IN ('lire','creer') AND (r.subperms IS NULL OR r.subperms='') WHERE u.login='att_71505';"
  dbe "INSERT IGNORE INTO llx_user_rights (entity,fk_user,fk_id) SELECT 1,u.rowid,r.id FROM llx_user u JOIN llx_rights_def r ON r.module='user' AND r.perms='user' AND r.subperms='lire' WHERE u.login='att_71510';"
}
# Self-heal: module-enable (web) and SQL seeding can PARTIALLY fail under rapid docker-exec load,
# leaving reinstall "done" but incomplete. Verify the 6 needed modules + 7 attacker rights are
# actually present, and retry the whole enable+seed until they are.
for _seed_try in 1 2 3 4 5; do
  echo "[lab] enable modules + seed attackers (attempt $_seed_try)"
  enable_modules; seed_attackers
  M6=$(dbe "SELECT COUNT(*) FROM llx_const WHERE name IN ('MAIN_MODULE_API','MAIN_MODULE_ADHERENT','MAIN_MODULE_FACTURE','MAIN_MODULE_SOCIETE','MAIN_MODULE_BANQUE','MAIN_MODULE_WEBPORTAL') AND value='1';")
  R7=$(dbe "SELECT COUNT(*) FROM llx_user_rights ur JOIN llx_user u ON u.rowid=ur.fk_user WHERE u.login LIKE 'att\\_715%';")
  [ "$M6" = "6" ] && [ "$R7" = "7" ] && break
done

# Readiness settle: ensure the accounting table exists (retry the load) and the app answers a
# real create round-trip, so a script launched immediately after does not race a busy DB.
for _try in 1 2 3; do
  [ -n "$(dbe "SELECT 1 FROM information_schema.tables WHERE table_schema='dolibarr_audit' AND table_name='llx_accounting_bookkeeping';")" ] && break
  for f in llx_accounting_bookkeeping-accounting.sql llx_accounting_bookkeeping-accounting.key.sql; do
    docker exec "$WEB" sh -c "cat $TBL/$f" 2>/dev/null | docker exec -i "$DBC" sh -c 'exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" dolibarr_audit' 2>/dev/null
  done
done
for _try in 1 2 3 4 5; do
  [ "$(curl -s -m5 -o /dev/null -w '%{http_code}' -H "$H" -H "DOLAPIKEY: $ADMINKEY" "$BASE/api/index.php/users/1")" = "200" ] && break
done
# Confirm the WRITE path is live (a create returns an id), not just that a GET answers -- the
# heaviest fixture (CVE-71506) otherwise races a DB still settling the seed writes. Probe with a
# throwaway third party until it round-trips, then delete it.
for _try in $(seq 1 20); do
  pid=$(curl -s -m5 -H "$H" -H "DOLAPIKEY: $ADMINKEY" -H 'Content-Type: application/json' -X POST \
        --data '{"name":"_readiness_probe","client":"1","country_id":"1"}' \
        "$BASE/api/index.php/thirdparties" | tr -d '"[:space:]' | grep -oE '^[0-9]+')
  if [ -n "$pid" ]; then
    curl -s -m5 -o /dev/null -H "$H" -H "DOLAPIKEY: $ADMINKEY" -X DELETE "$BASE/api/index.php/thirdparties/$pid"
    break
  fi
done

mods=$(dbe "SELECT COUNT(*) FROM llx_const WHERE name IN ('MAIN_MODULE_API','MAIN_MODULE_ADHERENT','MAIN_MODULE_FACTURE','MAIN_MODULE_SOCIETE','MAIN_MODULE_WEBPORTAL') AND value='1';")
atts=$(dbe "SELECT COUNT(*) FROM llx_user WHERE login LIKE 'att\\_715%';")
rights=$(dbe "SELECT COUNT(*) FROM llx_user_rights ur JOIN llx_user u ON u.rowid=ur.fk_user WHERE u.login LIKE 'att\\_715%';")
code=$(curl -s -m5 -o /dev/null -w '%{http_code}' -H "$H" -H "DOLAPIKEY: $ADMINKEY" "$BASE/api/index.php/users/1")
echo "[lab] READY  modules=$mods/5  attackers=$atts/4  attacker_rights=$rights  admin_api=$code  profile(https=$HTTPS csrf=$CSRF prod=$PROD)"
