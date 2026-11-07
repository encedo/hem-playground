#!/bin/sh
# Run on attest.encedo.com as root once the CNAME from setup.sh resolves:
#   sh issue.sh
# One certificate for playground.ence.do and *.playground.ence.do; certbot renews it
# itself with the same hook, and the existing deploy hook reloads nginx.
set -e
dig +short _acme-challenge.playground.ence.do CNAME | grep -q acme.playground.ence.do || { echo "the CNAME _acme-challenge.playground.ence.do is not there yet"; exit 1; }
certbot certonly --non-interactive --agree-tos -m support@encedo.com \
  --manual --preferred-challenges dns --manual-auth-hook /etc/acme-dns/certbot-hook.sh \
  --cert-name playground.ence.do -d playground.ence.do -d '*.playground.ence.do'
ls -l /etc/letsencrypt/live/playground.ence.do/
