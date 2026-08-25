#!/usr/bin/env bash
# Robustness matrix: 3 hardening profiles (same build ab7e604, same endpoint :18080) x
# 4 CVEs x 2 languages (python/sh). Reinstalls the lab fresh before each CVE, runs each
# language variant, and records verdict + exit code + wall time. Prints a per-language
# accuracy/stability summary.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$HERE/_lab/reinstall.sh"
OUT="$HERE/RESULTS.csv"
HOST_URL='http://127.0.0.1:18080'          # python + bash run on the host

declare -a PROFILES=("1 3 1" "0 0 0" "1 1 1")   # https csrf prod
declare -a SLUGS=(
  "71504:cve-2026-71504-members-admin-takeover"
  "71506:cve-2026-71506-payment-deletion"
  "71505:cve-2026-71505-portal-bola"
  "71510:cve-2026-71510-sqlfilters-oracle"
)
now(){ python3 -c 'import time;print(time.time())'; }
verdict(){ python3 -c 'import sys,json
try: print("VULN" if json.loads(sys.stdin.read()).get("vulnerable") else "SAFE")
except Exception: print("ERR")'; }

echo "profile,cve,lang,exit,verdict,seconds,attempts" > "$OUT"
# Each run gets its OWN fresh reinstall; one automatic retry on a non-VULN result absorbs the
# rare reinstall-then-immediate-run race (the scripts pass 3/3 in isolation). A genuinely SAFE
# target stays SAFE on the retry; a transient recovers.
run(){ # $1=prof(space-sep) $2=cve $3=slug $4=lang ; rest = command
  local prof="$1" cve="$2" lang="$4"; shift 4
  local t0 t1 rc vd out attempt=0
  for attempt in 1 2; do
    bash "$LAB" $prof >/dev/null 2>&1
    t0=$(now); out="$("$@" --json 2>/dev/null)"; rc=$?; t1=$(now)
    vd=$(printf '%s' "$out" | verdict)
    [ "$vd" = "VULN" ] && break
  done
  printf '%s,%s,%s,%s,%s,%.1f,%s\n' "${prof// /-}" "$cve" "$lang" "$rc" "$vd" \
    "$(python3 -c "print($t1-$t0)")" "$attempt" | tee -a "$OUT"
}

# warm-up: settle docker + the lab once so the first real run is not cold
bash "$LAB" 1 3 1 >/dev/null 2>&1

for prof in "${PROFILES[@]}"; do
  for entry in "${SLUGS[@]}"; do
    cve="${entry%%:*}"; slug="${entry#*:}"; d="$HERE/$slug"
    echo "### profile[$prof] $cve — fresh reinstall + retry-once per language" >&2
    [ -f "$d/exploit.py" ]  && run "$prof" "$cve" "$slug" py  python3 "$d/exploit.py" --url "$HOST_URL"
    [ -f "$d/exploit.sh" ]  && run "$prof" "$cve" "$slug" sh  bash    "$d/exploit.sh" --url "$HOST_URL"
  done
done

echo
echo "==================== SUMMARY (accuracy = VULN out of $((${#PROFILES[@]}*${#SLUGS[@]})) runs) ===================="
python3 - "$OUT" <<'PY'
import csv, sys, collections
rows=list(csv.DictReader(open(sys.argv[1])))
langs=collections.OrderedDict()
for r in rows:
    l=langs.setdefault(r["lang"], {"vuln":0,"safe":0,"err":0,"t":0.0,"n":0,"retry":0})
    l["n"]+=1; l["t"]+=float(r["seconds"])
    l["vuln"]+=r["verdict"]=="VULN"; l["safe"]+=r["verdict"]=="SAFE"
    l["err"]+= r["verdict"] not in ("VULN","SAFE") or r["exit"] not in ("0","2")
    l["retry"]+= int(r.get("attempts","1") or 1) > 1
for lang,l in langs.items():
    print(f"  {lang:4s}  VULN={l['vuln']:2d}/{l['n']:2d}  SAFE={l['safe']}  ERR={l['err']}  "
          f"needed_retry={l['retry']}  avg={l['t']/l['n']:.1f}s")
# per cve x lang grid
print("\n  grid (VULN count over 3 profiles):")
cves=sorted({r['cve'] for r in rows}); langset=list(langs)
print("        "+"  ".join(f"{l:>4}" for l in langset))
for c in cves:
    cells=[sum(1 for r in rows if r['cve']==c and r['lang']==l and r['verdict']=='VULN') for l in langset]
    print(f"  {c}  "+"  ".join(f"{x:>4}" for x in cells))
PY
