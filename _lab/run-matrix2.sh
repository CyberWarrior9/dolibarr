#!/usr/bin/env bash
# Gentle robustness matrix: ONE reinstall per (profile, CVE); the three language variants then run
# back-to-back on that install with UNIQUE fixtures (no collision, no rapid reinstall churn -- which
# on a single shared container intermittently produces an incompletely-seeded lab). 3 profiles x
# 4 CVEs x 3 languages, same build (ab7e604) and endpoint (:18080).
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$HERE/_lab/reinstall.sh"; OUT="$HERE/RESULTS.csv"; URL='http://127.0.0.1:18080'
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

echo "profile,cve,lang,exit,verdict,seconds" > "$OUT"
bash "$LAB" 1 3 1 >/dev/null 2>&1   # warm-up

for prof in "${PROFILES[@]}"; do
  for entry in "${SLUGS[@]}"; do
    cve="${entry%%:*}"; d="$HERE/${entry#*:}"
    echo "### profile[$prof] $cve — one reinstall, 3 langs (unique fixtures)" >&2
    bash "$LAB" $prof >/dev/null 2>&1
    for L in py sh; do
      case "$L" in py) x=(python3 "$d/exploit.py");; sh) x=(bash "$d/exploit.sh");; esac
      uniq=()
      case "$cve" in
        71510) uniq=(--victim-login "victim_$L");;
        71505) uniq=(--portal-login "portal_$L");;
      esac
      t0=$(now); out=$("${x[@]}" --url "$URL" "${uniq[@]}" --json 2>/dev/null); rc=$?; t1=$(now)
      vd=$(printf '%s' "$out" | vpass)
      printf '%s,%s,%s,%s,%s,%.1f\n' "${prof// /-}" "$cve" "$L" "$rc" "$vd" "$(python3 -c "print($t1-$t0)")" | tee -a "$OUT"
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
