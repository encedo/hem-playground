#!/bin/sh
# Run hem-api-tester (branch fw-1.3.x) against a local playground module, in a PHP container.
#   test/run-tester.sh [test_N.php ...]        (default: every test, in order)
# HEM_DOMAIN (default test.localhost); TESTER_DIR (default ../hem-api-tester, on branch fw-1.3.x).
# EXTAUTH=1: run ExtAuth_Simulator.php (the phone app) in the background, for test_5 / test_6.
# TESTER_INPUT: what to type at the prompts (test_7 subtest number, test_8 Enter), e.g. TESTER_INPUT='2\n'.
set -e
cd "$(dirname "$0")/.."
TESTER_DIR=${TESTER_DIR:-../hem-api-tester}
HEM_DOMAIN=${HEM_DOMAIN:-test.localhost}
[ "$(git -C "$TESTER_DIR" branch --show-current)" = fw-1.3.x ] || echo "warning: $TESTER_DIR is not on fw-1.3.x" >&2
docker image inspect hem-tester:php >/dev/null 2>&1 || docker build -q -t hem-tester:php -f test/tester.Dockerfile test >/dev/null
TESTS=${*:-$(cd "$TESTER_DIR" && ls test_*.php | sort -t_ -k2 -n | tr '\n' ' ')}
case "$HEM_DOMAIN" in *.localhost) ADDHOST="--add-host $HEM_DOMAIN:127.0.0.1" ;; *) ADDHOST= ;; esac
docker run --rm --network host $ADDHOST \
  -e HEM_DOMAIN="$HEM_DOMAIN" -e AUTHKEY -e DEBUG -e TESTER \
  -v "$(realpath "$TESTER_DIR"):/tester:ro" -v "$PWD/test/tester-config.php:/cfg/append.php:ro" \
  -v "$PWD/.local/caddy-root.crt:/usr/local/share/ca-certificates/playground.crt:ro" \
  -i -e EXTAUTH -e TESTER_INPUT \
  hem-tester:php sh -c "update-ca-certificates >/dev/null 2>&1; mkdir -p /run/t && cp -r /tester/. /run/t/ && cat /cfg/append.php >> /run/t/config.php && cd /run/t && rm -rf out && mkdir -p out \
    && { [ -n \"\$EXTAUTH\" ] && { php ExtAuth_Simulator.php > /tmp/sim.log 2>&1 & sleep 1; } || true; } \
    && for t in $TESTS; do echo \"=== \$t\"; printf \"\$TESTER_INPUT\" | php \$t; done; [ -n \"\$EXTAUTH\" ] && { echo '--- simulator'; tail -20 /tmp/sim.log; } || true"
