#!/bin/sh
# Run on attest.encedo.com as root, from a copy of deploy/acme-dns/:
#   sh setup.sh
# 1. acme-dns in a container (host network: DNS on 38.133.142.202:53, API on 127.0.0.1:8053)
# 2. port 53 open in ufw (udp + tcp)
# 3. one acme-dns account for the playground certificate, kept in /etc/acme-dns/playground.json
# 4. prints the CNAME to add in DigitalOcean
set -e
cd "$(dirname "$0")"
install -d -m 755 /etc/acme-dns /var/lib/acme-dns
install -m 644 config.cfg /etc/acme-dns/config.cfg
install -m 755 certbot-hook.sh /etc/acme-dns/certbot-hook.sh
docker rm -f acme-dns >/dev/null 2>&1 || true
docker run -d --name acme-dns --restart unless-stopped --network host \
  -v /etc/acme-dns:/etc/acme-dns:ro -v /var/lib/acme-dns:/var/lib/acme-dns \
  joohoi/acme-dns:v2.0.2 >/dev/null
sleep 2
docker logs acme-dns 2>&1 | tail -3
ufw allow 53/udp comment 'acme-dns playground'
ufw allow 53/tcp comment 'acme-dns playground'
if [ ! -s /etc/acme-dns/playground.json ]; then
  curl -s -X POST http://127.0.0.1:8053/register > /etc/acme-dns/playground.json
  chmod 600 /etc/acme-dns/playground.json
fi
echo
echo "Add in DigitalOcean (zone ence.do):"
echo "  _acme-challenge.playground.ence.do  CNAME  $(jq -r .fulldomain /etc/acme-dns/playground.json)."
