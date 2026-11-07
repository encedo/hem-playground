#!/bin/sh
# Run hem-api-tester (branch fw-1.3.x) against a local playground module, in a PHP container.
#   test/run-tester.sh [test_N.php ...]        (default: every test, in order)
# HEM_DOMAIN (default test.localhost); TESTER_DIR (default ../hem-api-tester, on branch fw-1.3.x).
set -e
cd "$(dirname "$0")/.."
TESTER_DIR=${TESTER_DIR:-../hem-api-tester}
HEM_DOMAIN=${HEM_DOMAIN:-test.localhost}
[ "$(git -C "$TESTER_DIR" branch --show-current)" = fw-1.3.x ] || echo "warning: $TESTER_DIR is not on fw-1.3.x" >&2
docker image inspect hem-tester:php >/dev/null 2>&1 || docker build -q -t hem-tester:php -f test/tester.Dockerfile test >/dev/null
TESTS=${*:-$(cd "$TESTER_DIR" && ls test_*.php | sort -t_ -k2 -n | tr '\n' ' ')}
docker run --rm --network host --add-host "$HEM_DOMAIN:127.0.0.1" \
  -e HEM_DOMAIN="$HEM_DOMAIN" -e AUTHKEY -e DEBUG -e TESTER \
  -v "$(realpath "$TESTER_DIR"):/tester:ro" -v "$PWD/test/tester-config.php:/cfg/append.php:ro" \
  -v "$PWD/.local/caddy-root.crt:/usr/local/share/ca-certificates/playground.crt:ro" \
  hem-tester:php sh -c "update-ca-certificates >/dev/null 2>&1; mkdir -p /run/t && cp -r /tester/. /run/t/ && cat /cfg/append.php >> /run/t/config.php && cd /run/t && for t in $TESTS; do echo \"=== \$t\"; php \$t; done"
