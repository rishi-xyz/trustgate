#!/usr/bin/env bash
# End-to-end local demo (INSECURE dev mode): execute -> verify -> replay -> tamper.
set -euo pipefail
cd "$(dirname "$0")/.."
make -s publish >/dev/null
PORT=${PORT:-18080}
bin/trustgate-server -addr ":$PORT" -mode dev -publisher-pub-file .trustgate-dev/publisher.pub \
  -registry registry/manifests >.trustgate-dev/server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for _ in $(seq 50); do curl -sf "localhost:$PORT/healthz" >/dev/null && break; sleep 0.1; done
INFO=$(curl -s "localhost:$PORT/.well-known/trustgate")
MEAS=$(echo "$INFO" | jq -r .measurement)
DEVTRUST=$(echo "$INFO" | jq -r .dev_trust)
V="-allow-dev -dev-trust $DEVTRUST -measurement $MEAS"

echo "== execute"
bin/trustgate exec -url "http://localhost:$PORT/mcp" -workload csv-stats \
  -input testdata/transactions.csv -args amount,supplier -out .trustgate-dev/receipt.json
echo; echo "== verify"
bin/trustgate verify .trustgate-dev/receipt.json $V
echo; echo "== replay"
bin/trustgate replay .trustgate-dev/receipt.json $V -wasm build/csv-stats.wasm -stdin testdata/transactions.csv
echo; echo "== attack: flip one input byte, replay must fail"
sed 's/50000.00/50000.01/' testdata/transactions.csv >.trustgate-dev/tampered.csv
bin/trustgate replay .trustgate-dev/receipt.json $V -wasm build/csv-stats.wasm -stdin .trustgate-dev/tampered.csv && { echo "UNEXPECTED PASS"; exit 1; } || echo "(failed as expected)"
echo; echo "== attack: edit receipt output hash, verify must fail"
jq '.receipt.output_sha256="sha256:0000000000000000000000000000000000000000000000000000000000000000"' \
  .trustgate-dev/receipt.json >.trustgate-dev/forged.json
bin/trustgate verify .trustgate-dev/forged.json $V && { echo "UNEXPECTED PASS"; exit 1; } || echo "(failed as expected)"
