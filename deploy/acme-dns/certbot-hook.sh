#!/bin/sh
# certbot --manual-auth-hook: put the validation value into acme-dns.
# acme-dns keeps the last two values, so playground.ence.do and *.playground.ence.do validate together.
set -e
ACC=/etc/acme-dns/playground.json
curl -sf -X POST http://127.0.0.1:8053/update \
  -H "X-Api-User: $(jq -r .username $ACC)" -H "X-Api-Key: $(jq -r .password $ACC)" \
  -d "{\"subdomain\":\"$(jq -r .subdomain $ACC)\",\"txt\":\"$CERTBOT_VALIDATION\"}" >/dev/null
sleep 5
