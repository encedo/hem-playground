#!/bin/sh
# Build the image on the server from this checkout, then (re)start it there.
#   deploy/deploy.sh [ssh-host]      (default attest.encedo.com)
# The build context (only the files the Dockerfile copies) goes over ssh into
# `docker build -`, so nothing of the source stays on the server; built there
# because the server is amd64 and a desk may not be. The server keeps its own
# /opt/hem-playground/.env (never copied from here).
set -e
cd "$(dirname "$0")/.."
HOST=${1:-attest.encedo.com}
[ -f manager/sdk/hem-sdk.js ] || { echo "submodules missing: git submodule update --init --recursive"; exit 1; }
scp -q deploy/compose.prod.yaml "$HOST:/opt/hem-playground/"
tar -c Dockerfile .dockerignore server manager/index.html manager/favicon.svg manager/app \
       manager/sdk/hem-sdk.js manager/sdk/hem-sdk.browser.js \
  | ssh "$HOST" 'docker build -q -t hem-playground:latest - >/dev/null && cd /opt/hem-playground && docker compose -f compose.prod.yaml up -d && docker image prune -f >/dev/null'
echo "deployed $(git rev-parse --short HEAD) to $HOST"
