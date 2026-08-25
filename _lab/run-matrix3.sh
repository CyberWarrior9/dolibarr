#!/usr/bin/env bash
# Definitive matrix. Repeated reinstalls of one shared container accumulate degradation (partial
# module-enable/seed) that fails ANY language equally; a container restart clears it. So: per
# profile we RESTART the web container, install once, then run all 12 script variants on that one
# healthy install with UNIQUE fixtures (no reinstall churn, no fixture collision). Same build
# (ab7e604) and endpoint (:18080); 3 profiles x 4 CVEs x 3 languages.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$HERE/_lab/reinstall.sh"; OUT="$HERE/RESULTS.csv"; URL='http://127.0.0.1:18080'
PROJ=dolibarr-cve-audit; COMPOSE_DIR=/private/tmp/dolibarr-cve-audit
declare -a PROFILES=("1 3 1" "0 0 0" "1 1 1")
declare -a SLUGS=(
  "71504:cve-2026-71504-members-admin-takeover"
  "71506:cve-2026-71506-payment-deletion"
  "71505:cve-2026-71505-portal-bola"
  "71510:cve-2026-71510-sqlfilters-oracle")
now(){ python3 -c 'import time;print(time.time())'; }
vpass(){ python3 -c 'import sys,json
try: print("VULN" if json.loads(sys.stdin.read())["vulnerable"] else "SAFE")
except Exception: print("ERR")'; }
wait_ready(){ local i; for i in $(seq 1 40); do [ "$(curl -s -m3 -o /dev/null -w '%{http_code}' "$URL/" 2>/dev/null)" != "000" ] && return; done; }

echo "profile,cve,lang,exit,verdict,seconds" > "$OUT"
for prof in "${PROFILES[@]}"; do
  echo "### profile[$prof]: restart container + single clean install" >&2
  ( cd "$COMPOSE_DIR" && docker compose -p "$PROJ" restart web >/dev/null 2>&1 )
  wait_ready
  bash "$LAB" $prof >/dev/null 2>&1
  for entry in "${SLUGS[@]}"; do
    cve="${entry%%:*}"; d="$HERE/${entry#*:}"
    for L in py sh; do
      case "$L" in py) x=(python3 "$d/exploit.py");; sh) x=(bash "$d/exploit.sh");; esac
      uniq=(); case "$cve" in 71510) uniq=(--victim-login "victim_$L");; 71505) uniq=(--portal-login "portal_$L");; esac
      t0=$(now); out=$("${x[@]}" --url "$URL" "${uniq[@]}" --json 2>/dev/null); rc=$?; t1=$(now)
      printf '%s,%s,%s,%s,%s,%.1f\n' "${prof// /-}" "$cve" "$L" "$rc" "$(printf '%s' "$out" | vpass)" \
        "$(python3 -c "print($t1-$t0)")" | tee -a "$OUT"
    done
  done
done

echo; echo "==================== SUMMARY (VULN out of 12) ===================="
python3 - "$OUT" <<'PY'
import csv,sys,collections
rows=list(csv.DictReader(open(sys.argv[1]))); L=collections.OrderedDict()
for r in rows:
    d=L.setdefault(r["lang"],{"v":0,"s":0,"e":0,"t":0.0,"n":0}); d["n"]+=1; d["t"]+=float(r["seconds"])
    d["v"]+=r["verdict"]=="VULN"; d["s"]+=r["verdict"]=="SAFE"; d["e"]+=r["verdict"]=="ERR"
for lang,d in L.items():
    print(f"  {lang:4s} VULN={d['v']:2d}/{d['n']:2d}  SAFE={d['s']}  ERR={d['e']}  avg={d['t']/d['n']:.1f}s")
print("\n  grid (VULN over 3 profiles):\n        "+"  ".join(f"{l:>4}" for l in L))
for c in sorted({r['cve'] for r in rows}):
    print(f"  {c}  "+"  ".join(f"{sum(1 for r in rows if r['cve']==c and r['lang']==l and r['verdict']=='VULN'):>4}" for l in L))
PY
