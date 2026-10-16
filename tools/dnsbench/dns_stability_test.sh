#!/usr/bin/env bash
# Standalone DNS daily-traffic / moderate-burst stability test for dnsbench 1.0.
# Does not modify the original bench_suite.sh, firmware, or project sources.
# Usage: bash dns_stability_test.sh SERVER [PORT=53] [DURATION=300]
# Examples:
#   DNSBENCH="$PWD/dnsbench" bash dns_stability_test.sh 192.168.31.7 53 300
#   DNSBENCH="$PWD/dnsbench" bash dns_stability_test.sh 192.168.31.7 53 600
# Defaults: steady 5 QPS, busy 12 QPS, burst 25 QPS for 3s each ~minute;
#          new names 1 QPS for 5s per cycle and 10% of the steady stream.
# All stages are open-loop (-r). No unthrottled dnsbench warmup/closed-loop.
set -Eeuo pipefail

usage() {
  cat >&2 <<'HELP'
Usage: bash dns_stability_test.sh SERVER [PORT=53] [DURATION_SECONDS=300]
Run for 300 seconds (5 min) or 600 seconds (10 min) for a typical test.
Environment options:
  DNSBENCH=./dnsbench      Path to existing dnsbench executable (required if not in ./ or PATH)
  BASE_QPS=5              Steady mixed traffic, 1..20
  BUSY_QPS=12             Busy period traffic, 1..30
  BURST_QPS=25            Short cached-name burst traffic, 1..60
  BURST_SECONDS=3         Burst length (1..6 s)
  MISS_QPS=1              Fresh random-name test QPS (1..3)
  MISS_PCT=10             Random names during steady traffic (0..15%)
  MISS_DOMAIN=dnsbench.invalid  Parent name for random test names
  CACHE_DOMAIN=www.baidu.com    One name for repeat/burst path
  NAMES_FILE=/path/names.txt    Optional warm/hot name list, dnsbench format
  TCP_EVERY=3             Once every N cycles, busy stage uses TCP; 0 disables
  FAILURE_PCT=15         Stop early when loss or errors >= this percent (min 3)
  SERVFAIL_PCT=20        Stop early when SERVFAIL >= this percent (min 3)
  TIMEOUT_MS=1500        Per-request timeout, 200..5000 ms
  RESULT_DIR=directory    Output folder (default stability-YYYYmmdd-HHMMSS)
Notes: bursts use repeated names and benefit from an enabled DNS cache; they are
not guaranteed to remain off the upstream. For upstream isolation, set
CACHE_DOMAIN to a local DNS rewrite and NAMES_FILE to other locally resolved names.
HELP
  exit 2
}
[[ ${1:-} != -h && ${1:-} != --help ]] || usage
[[ $# -ge 1 && $# -le 3 ]] || usage
SERVER=$1
PORT=${2:-53}
DURATION=${3:-300}
BASE_QPS=${BASE_QPS:-5}
BUSY_QPS=${BUSY_QPS:-12}
BURST_QPS=${BURST_QPS:-25}
BURST_SECONDS=${BURST_SECONDS:-3}
MISS_QPS=${MISS_QPS:-1}
MISS_PCT=${MISS_PCT:-10}
MISS_DOMAIN=${MISS_DOMAIN:-dnsbench.invalid}
CACHE_DOMAIN=${CACHE_DOMAIN:-www.baidu.com}
TCP_EVERY=${TCP_EVERY:-3}
FAILURE_PCT=${FAILURE_PCT:-15}
SERVFAIL_PCT=${SERVFAIL_PCT:-20}
TIMEOUT_MS=${TIMEOUT_MS:-1500}
RESULT_DIR=${RESULT_DIR:-stability-$(date +%Y%m%d-%H%M%S)}

valid_int() {
  local name=$1 low=$2 high=$3 value=${!1}
  if ! [[ $value =~ ^[0-9]+$ ]] || (( 10#$value < low || 10#$value > high )); then
    printf 'Invalid %s: %s; expected integer %s..%s\n' "$name" "$value" "$low" "$high" >&2
    exit 2
  fi
}
valid_int PORT 1 65535
valid_int DURATION 30 3600
valid_int BASE_QPS 1 20
valid_int BUSY_QPS 1 30
valid_int BURST_QPS 1 60
valid_int BURST_SECONDS 1 6
valid_int MISS_QPS 1 3
valid_int MISS_PCT 0 15
valid_int TCP_EVERY 0 100
valid_int FAILURE_PCT 1 100
valid_int SERVFAIL_PCT 1 100
valid_int TIMEOUT_MS 200 5000
for nm in MISS_DOMAIN CACHE_DOMAIN; do
  v=${!nm}
  if [[ ! $v =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ || ${#v} -gt 190 ]]; then
    printf 'Invalid %s: %s\n' "$nm" "$v" >&2
    exit 2
  fi
done

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BENCH=${DNSBENCH:-}
if [[ -z $BENCH ]]; then
  for candidate in "$PWD/dnsbench" "$HERE/dnsbench" "$(command -v dnsbench || true)"; do
    if [[ -n $candidate && -f $candidate && -x $candidate ]]; then BENCH=$candidate; break; fi
  done
fi
[[ -n $BENCH && -f $BENCH && -x $BENCH ]] || { echo 'No dnsbench executable found; set DNSBENCH=/path/to/dnsbench' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 required' >&2; exit 1; }
mkdir -p -- "$RESULT_DIR"
RESULT_DIR=$(cd -- "$RESULT_DIR" && pwd)
[[ ! -e "$RESULT_DIR/summary.csv" ]] || { echo "Refusing to overwrite $RESULT_DIR/summary.csv" >&2; exit 1; }

if [[ ${NAMES_FILE:-} ]]; then
  [[ -f $NAMES_FILE ]] || { echo "NAMES_FILE not found: $NAMES_FILE" >&2; exit 1; }
  cp -- "$NAMES_FILE" "$RESULT_DIR/names.txt"
else
  cat > "$RESULT_DIR/names.txt" <<'NAMES'
www.baidu.com
www.qq.com
www.bilibili.com
www.microsoft.com
NAMES
fi
printf '%s\n' "$CACHE_DOMAIN" > "$RESULT_DIR/burst_name.txt"
[[ -s "$RESULT_DIR/names.txt" ]] || { echo 'NAMES_FILE empty' >&2; exit 1; }

case "$SERVER" in
  *:*) TARGET="[$SERVER]:$PORT" ;;
  *) TARGET="$SERVER:$PORT" ;;
esac
cat > "$RESULT_DIR/config.txt" <<CFG
target=$TARGET
seconds=$DURATION
steady_qps=$BASE_QPS
busy_qps=$BUSY_QPS
burst_qps=$BURST_QPS
burst_seconds=$BURST_SECONDS
fresh_name_qps=$MISS_QPS
steady_random_percent=$MISS_PCT
random_domain=$MISS_DOMAIN
cached_burst_domain=$CACHE_DOMAIN
tcp_cycle_interval=$TCP_EVERY
request_timeout_ms=$TIMEOUT_MS
start_utc=$(date -u +%FT%TZ)
CFG
printf 'stage,kind,requested_seconds,requested_qps,sent,answered,timeouts,errors,unanswered,servfail,nxdomain,qps,p50_ms,p95_ms,p99_ms,max_ms\n' > "$RESULT_DIR/summary.csv"

finish() {
  local status=$?
  trap - EXIT
  python3 - "$RESULT_DIR" "$status" <<'PY'
import csv, os, sys
out, status = sys.argv[1:]
rows = []
try:
    with open(os.path.join(out, 'summary.csv'), newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
except (OSError, csv.Error):
    pass
def total(k): return sum(int(r[k]) for r in rows)
lines = [
    f"Result directory: {out}",
    f"Finished stages: {len(rows)}",
    f"Requests: {total('sent')} | Answered: {total('answered')}",
    f"Timeouts: {total('timeouts')} | Errors: {total('errors')} | Unanswered: {total('unanswered')}",
    f"SERVFAIL: {total('servfail')} | NXDOMAIN (not a failure): {total('nxdomain')}",
    "Worst per-stage p99: " + (f"{max(float(r['p99_ms']) for r in rows):.3f} ms" if rows else "N/A"),
    "Note: worst stage p99 is NOT a whole-test aggregated percentile.",
    f"Exit status: {status}",
]
with open(os.path.join(out, 'final_summary.txt'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines)+'\n')
print('\n'+'\n'.join(lines))
PY
}
trap finish EXIT
trap 'echo "Interrupted: stopping test" >&2; exit 130' INT TERM

# Probe only once. Never use --scenario cache: that triggers unthrottled prewarm.
echo "Checking $TARGET ..."
if ! "$BENCH" -s "$TARGET" --query "$CACHE_DOMAIN" -t A -w "$TIMEOUT_MS" \
    > "$RESULT_DIR/connectivity.txt" 2>&1; then
  echo "DNS preflight failed. See $RESULT_DIR/connectivity.txt" >&2
  exit 1
fi
# One A query primes the burst name; if TTL expires later, subsequent cache
# misses can still be sent upstream (not an upstream-isolated test).

echo "Running ${DURATION}s stability test -> $TARGET"
echo "steady ${BASE_QPS}qps, busy ${BUSY_QPS}qps, burst ${BURST_QPS}qps x ${BURST_SECONDS}s, fresh-name ${MISS_QPS}qps"
echo "Results: $RESULT_DIR"
START=$(date +%s)
END=$((START + DURATION))
SEQ=0
STOP_REASON=''

# Keep each phase inside the remaining wall-clock budget.
remaining() { local n; n=$(date +%s); echo "$(( END > n ? END - n : 0 ))"; }
phase() {  # phase NAME KIND SECONDS RATE [dnsbench arguments...]
  local name=$1 kind=$2 wanted=$3 rate=$4
  shift 4
  local left sec ret
  left=$(remaining)
  (( left > 0 )) || return 0
  sec=$wanted
  (( sec <= left )) || sec=$left
  (( sec >= 1 )) || return 0
  SEQ=$((SEQ+1))
  local slug
  printf -v slug '%03d_%s' "$SEQ" "$name"
  echo "[$(date '+%H:%M:%S')] $slug: $sec s @ ${rate} QPS ($kind)"
  ret=0
  "$BENCH" -s "$TARGET" -r "$rate" -d "$sec" -T 1 -w "$TIMEOUT_MS" \
    -i 0 --json "$@" > "$RESULT_DIR/$slug.json" 2> "$RESULT_DIR/$slug.err" || ret=$?
  if ! python3 - "$RESULT_DIR/$slug.json" "$RESULT_DIR/summary.csv" "$slug" "$kind" "$sec" "$rate" \
    "$FAILURE_PCT" "$SERVFAIL_PCT" "$ret" <<'PY'
import csv, json, sys
filename, summary, name, kind, duration, rate, max_fail, max_servfail, result = sys.argv[1:]
try:
    with open(filename, encoding='utf-8') as f: d = json.load(f)
    sent = int(d['sent'])
    answered = int(d['answered'])
    to = int(d['timeouts'])
    err = int(d.get('errors', 0))
    not_answered = int(d.get('unanswered', 0))
    sf = int(d.get('rcode', {}).get('SERVFAIL', 0))
    nx = int(d.get('rcode', {}).get('NXDOMAIN', 0))
    lat = d['latency_ms']
    row = [name, kind, duration, rate, sent, answered, to, err, not_answered, sf, nx,
           d['qps'], lat['p50'], lat['p95'], lat['p99'], lat['max']]
    with open(summary, 'a', newline='', encoding='utf-8') as f:
        csv.writer(f).writerow(row)
    loss = to + err + not_answered
    print(f"  answered {answered}/{sent}; p50={lat['p50']:.3f} ms  p99={lat['p99']:.3f} ms; lost={loss}, SERVFAIL={sf}")
    if sent == 0 or int(result):
        print('  STOP: benchmark failed or no packets sent', file=sys.stderr)
        sys.exit(21)
    if sent >= 10 and loss >= 3 and 100 * loss >= sent * int(max_fail):
        print('  STOP: failure threshold crossed', file=sys.stderr)
        sys.exit(22)
    if sent >= 10 and sf >= 3 and 100 * sf >= sent * int(max_servfail):
        print('  STOP: SERVFAIL threshold crossed', file=sys.stderr)
        sys.exit(23)
except Exception as exc:
    print(f'  STOP: cannot parse result: {exc}', file=sys.stderr)
    sys.exit(24)
PY
  then
    echo "Stopping on $slug; see $RESULT_DIR/$slug.json and .$slug.err" >&2
    exit 1
  fi
}

cooldown() {
  local sec=$1 left
  left=$(remaining)
  (( sec <= left )) || sec=$left
  if (( sec > 0 )); then
    echo "[$(date '+%H:%M:%S')] idle/cooldown ${sec}s"
    sleep "$sec"
  fi
}

cycle=0
while (( $(remaining) > 0 )); do
  cycle=$((cycle+1))
  echo "========== cycle $cycle =========="
  phase "steady_${cycle}" steady-mixed 35 "$BASE_QPS" --scenario mixed \
        --miss-pct "$MISS_PCT" --domain "$MISS_DOMAIN" \
        --random -f "$RESULT_DIR/names.txt" -m A:65,AAAA:30,HTTPS:5
  phase "miss_${cycle}" fresh-names 5 "$MISS_QPS" --scenario miss \
        --domain "$MISS_DOMAIN" -t A -f "$RESULT_DIR/names.txt"
  if (( TCP_EVERY > 0 && cycle % TCP_EVERY == 0 )); then
    phase "busy_tcp_${cycle}" tcp-normal 10 3 --tcp -f "$RESULT_DIR/names.txt" -m A:70,AAAA:30
  else
    phase "busy_udp_${cycle}" udp-normal 10 "$BUSY_QPS" -f "$RESULT_DIR/names.txt" -m A:65,AAAA:30,HTTPS:5
  fi
  # Re-prime the repeated name (one request) shortly before the burst.
  # The targeted burst remains relatively light (default 25 QPS x 3s).
  if (( $(remaining) > BURST_SECONDS + 2 )); then
    "$BENCH" -s "$TARGET" --query "$CACHE_DOMAIN" -t A -w "$TIMEOUT_MS" \
      > "$RESULT_DIR/preburst_${cycle}.txt" 2>&1 || {
        echo "Preburst DNS probe failed; stopping" >&2; exit 1;
      }
  fi
  phase "burst_${cycle}" mild-burst "$BURST_SECONDS" "$BURST_QPS" -f "$RESULT_DIR/burst_name.txt" -t A
  phase "recovery_${cycle}" recovery 5 4 -f "$RESULT_DIR/names.txt" -m A:70,AAAA:30
  cooldown 2
  # Guard against unexpected non-advancing wall clock in partial-test modes.
done
