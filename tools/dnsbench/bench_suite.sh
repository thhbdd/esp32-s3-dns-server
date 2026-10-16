#!/usr/bin/env bash
# Standard benchmark suite for the ESP32-S3 DNS server.
#
#   tools/dnsbench/bench_suite.sh 192.168.1.53 [port] [seconds]
#
# Runs the cache, max-throughput, rate (latency), miss and TCP scenarios and
# saves every result as JSON in ./bench-<date>/ plus a summary table.
set -euo pipefail
SERVER=${1:?usage: $0 SERVER [PORT] [SECONDS]}
PORT=${2:-53}
SECS=${3:-10}
HERE=$(cd "$(dirname "$0")" && pwd)
BENCH=${DNSBENCH:-}
if [ -z "$BENCH" ]; then
  for c in "$HERE/../../build-host/dnsbench" "$HERE/../../build-rel/dnsbench" "$(command -v dnsbench || true)"; do
    if [ -n "$c" ] && [ -x "$c" ]; then BENCH=$c; break; fi
  done
fi
if [ -z "$BENCH" ]; then
  BENCH=$(mktemp -d)/dnsbench
  echo "building dnsbench..."
  cc -O2 -pthread -o "$BENCH" "$HERE/dnsbench.c" -lm
fi
OUT=bench-$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
case "$SERVER" in
  *:*) S="[$SERVER]:$PORT" ;; # IPv6 address
  *) S="$SERVER:$PORT" ;;
esac

run() { # name args...
  local name=$1; shift
  printf '%-34s' "$name"
  if "$BENCH" -s "$S" -d "$SECS" --json "$@" > "$OUT/$name.json" 2> "$OUT/$name.err"; then :; fi
  python3 - "$OUT/$name.json" <<'PY' || sed 's/^/    /' "$OUT/$name.err"
import json, sys
try:
    j = json.load(open(sys.argv[1]))
except Exception:
    print("failed"); sys.exit(1)
l = j["latency_ms"]
lost = j["timeouts"] + j.get("unanswered", 0)
print("%9.0f qps  p50 %7.3f  p99 %7.3f  p99.9 %7.3f ms  lost %d  SERVFAIL %d" %
      (j["qps"], l["p50"], l["p99"], l["p999"], lost, j["rcode"]["SERVFAIL"]))
PY
}

echo "dnsbench suite -> $S, ${SECS}s per scenario, results in $OUT/"
"$BENCH" -s "$S" --query www.baidu.com > "$OUT/check.txt" 2>&1 || { cat "$OUT/check.txt"; echo "server not answering"; exit 1; }
run cache_c1        --scenario cache -c 1
run cache_c16       --scenario cache -c 16
run cache_c64       --scenario cache -c 64
run cache_rate500   --scenario cache -r 500
run cache_rate2000  --scenario cache -r 2000
run mixed20_rate500 --scenario mixed --miss-pct 20 -r 500
run miss_rate100    --scenario miss -r 100
run tcp_c8          --scenario cache --tcp -c 8
run aaaa_https_mix  --scenario cache -m A:60,AAAA:30,HTTPS:10 -c 16
echo "done: $OUT/"
