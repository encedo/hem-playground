#!/bin/sh
# Build the image here, copy it to the server, (re)start it there.
#   deploy/deploy.sh [ssh-host]      (default attest.encedo.com)
# The server keeps its own /opt/hem-playground/.env (never copied from here).
set -e
cd "$(dirname "$0")/.."
HOST=${1:-attest.encedo.com}
docker build -t hem-playground:latest .
docker save hem-playground:latest | gzip > .local/hem-playground.tar.gz
scp .local/hem-playground.tar.gz deploy/compose.prod.yaml "$HOST:/opt/hem-playground/"
ssh "$HOST" 'cd /opt/hem-playground && gunzip -c hem-playground.tar.gz | docker load && docker compose -f compose.prod.yaml up -d && docker image prune -f >/dev/null'
