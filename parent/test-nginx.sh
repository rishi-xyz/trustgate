#!/usr/bin/env bash
# Validates parent/nginx-trustgate.conf with real nginx (in Docker) using a
# secret of the SAME LENGTH install.sh generates (64 hex characters): a short
# test secret once hid an "increase map_hash_bucket_size" failure that only
# appeared on the instance.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
secret=$(openssl rand -hex 32)
sed "s/__ORIGIN_SECRET__/$secret/" parent/nginx-trustgate.conf > "$tmp/trustgate.conf"
docker run --rm -v "$tmp":/etc/nginx/conf.d:ro nginx:alpine nginx -t
