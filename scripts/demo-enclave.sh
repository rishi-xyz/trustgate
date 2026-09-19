#!/usr/bin/env bash
# Guided TrustGate demo. Runs from the laptop against a running server:
#   real enclave:  TRUSTGATE_URL=http://<ip>:8443 PCR=<enclave PCR0> scripts/demo-enclave.sh
#   local rehearsal (insecure dev mode): MODE=dev TRUSTGATE_URL=http://localhost:18080 scripts/demo-enclave.sh
#
# Optional:
#   PAUSE=0            run straight through instead of waiting for Enter at each step
#   DEMO_SEALED=1      also run the confidential-job section (needs the data owner's AWS
#                      credentials in the environment when MODE is not dev)
#   SSH_TARGET=ec2-user@<ip> SSH_KEY=<key.pem>
#                      also run the parent-side proofs (direct KMS decrypt denied, packet capture)
set -uo pipefail
cd "$(dirname "$0")/.."

URL=${TRUSTGATE_URL:?set TRUSTGATE_URL, e.g. http://1.2.3.4:8443}
MCP="$URL/mcp"
MODE=${MODE:-nitro}
PAUSE=${PAUSE:-1}
D=.demo
mkdir -p "$D"

bold() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
run()  { printf '\033[2m$ %s\033[0m\n' "$*"; "$@"; }
step() { bold "$1"; [ "$PAUSE" = 1 ] && read -r -p "   [Enter to run] " _; return 0; }
expect_fail() { if "$@"; then echo "UNEXPECTED SUCCESS"; FAILED=1; else echo "   ^ refused, as expected"; fi; }
FAILED=0

# ---- preflight: are we talking to the build we think we are? -------------------------
INFO=$(curl -s -m 10 "$URL/.well-known/trustgate") || { echo "cannot reach $URL"; exit 1; }
MODE_REPORTED=$(echo "$INFO" | jq -r .mode)
MEAS=$(echo "$INFO" | jq -r .measurement)
if [ "$MODE" = dev ]; then
  V="-allow-dev -dev-trust $(echo "$INFO" | jq -r .dev_trust) -measurement $MEAS"
  SEAL_KMS=${SEAL_KMS:-dev}
  echo "NOTE: rehearsal against a DEV-mode server. Nothing here is hardware-attested."
else
  : "${PCR:?set PCR to the enclave PCR0 you expect}"
  if [ "$MODE_REPORTED" != nitro ] || [ "$MEAS" != "$PCR" ]; then
    echo "PREFLIGHT FAILED: server reports mode=$MODE_REPORTED measurement=$MEAS"
    echo "                  expected mode=nitro measurement=$PCR"; exit 1
  fi
  V="-measurement $PCR"
  SEAL_KMS=${SEAL_KMS:-aws:alias/trustgate-demo}
fi
echo "server: mode=$MODE_REPORTED measurement=${MEAS:0:32}…"

# ---- 1. run a job and verify it independently ----------------------------------------
step "1. An agent's job runs in the enclave and returns a signed receipt"
run bin/trustgate exec -url "$MCP" -workload csv-stats -input testdata/transactions.csv -args amount,supplier -out $D/receipt.json

step "2. Anyone can verify it independently: signature, real Nitro attestation, key binding, pinned measurement"
run bin/trustgate verify $D/receipt.json $V

step "3. ...and replay it on this machine: same code + same input = same output hash"
run bin/trustgate replay $D/receipt.json $V -wasm build/csv-stats.wasm -stdin testdata/transactions.csv | tail -4

# ---- 2. attacks ------------------------------------------------------------------------
step "4. Attack: change one byte of the input, then replay"
sed 's/50000.00/50000.01/' testdata/transactions.csv > $D/tampered.csv
expect_fail bin/trustgate replay $D/receipt.json $V -wasm build/csv-stats.wasm -stdin $D/tampered.csv | tail -3

step "5. Attack: edit the receipt (overwrite the output hash), then verify"
jq '.receipt.output_sha256="sha256:0000000000000000000000000000000000000000000000000000000000000000"' $D/receipt.json > $D/forged.json
expect_fail bin/trustgate verify $D/forged.json $V | tail -4

step "6. Attack: verify against the wrong enclave measurement"
BAD=${V/-measurement */-measurement 00}
expect_fail bin/trustgate verify $D/receipt.json $BAD | tail -3

# ---- 3. binary + async -----------------------------------------------------------------
step "7. Binary input and a long-running async job"
head -c 100000 /dev/urandom > $D/blob.bin
run bin/trustgate exec -url "$MCP" -workload hash-bytes -input $D/blob.bin -out $D/blob-receipt.json
echo "local sha256: $(sha256sum $D/blob.bin | cut -d' ' -f1)"
run bin/trustgate exec -async -url "$MCP" -workload primes -args 60000000 -out $D/async-receipt.json

# ---- 4. confidential job ---------------------------------------------------------------
if [ "${DEMO_SEALED:-0}" = 1 ]; then
  step "8. Confidential job: input encrypted by the data owner, result sealed to the owner's key"
  run bin/trustgate seal -url "$MCP" -workload csv-stats -args amount,supplier -input testdata/transactions.csv \
      -out $D/sealed.json -recipient $D/recipient.key -kms "$SEAL_KMS" -region "${AWS_REGION:-ap-south-1}"
  echo "what an untrusted parent can see of the input:"; head -c 260 $D/sealed.json; echo " ..."
  run bin/trustgate exec -url "$MCP" -workload csv-stats -sealed $D/sealed.json -out $D/conf.json
  run bin/trustgate verify $D/conf.json $V | tail -3
  run bin/trustgate replay $D/conf.json $V -salts $D/conf.json.salts.json -wasm build/csv-stats.wasm -stdin testdata/transactions.csv | tail -3

  step "9. Attack: the parent points the sealed input at a different approved workload"
  expect_fail bin/trustgate exec -url "$MCP" -workload hash-bytes -sealed $D/sealed.json -out $D/evil.json

  # ---- 5. parent-side proofs (need SSH to the instance) --------------------------------
  if [ -n "${SSH_TARGET:-}" ]; then
    SSH="ssh -i ${SSH_KEY:?set SSH_KEY} -o StrictHostKeyChecking=accept-new $SSH_TARGET"
    step "10. What the parent instance sees on the wire: sealed job vs the same job unsealed"
    $SSH 'sudo rm -f /tmp/demo-*.pcap' >/dev/null 2>&1
    $SSH -f 'sudo sh -c "nohup timeout 40 tcpdump -i any -s0 -w /tmp/demo-sealed.pcap port 8443 >/dev/null 2>&1 &"'; sleep 3
    bin/trustgate exec -url "$MCP" -workload csv-stats -sealed $D/sealed.json -out $D/conf2.json >/dev/null
    sleep 2; $SSH 'sudo pkill tcpdump; sleep 1'
    echo "sealed job, plaintext words seen by the parent:  $($SSH 'sudo strings /tmp/demo-sealed.pcap | grep -ciE "acme|beta|gamma|anomalies|stddev"')"
    $SSH -f 'sudo sh -c "nohup timeout 40 tcpdump -i any -s0 -w /tmp/demo-plain.pcap port 8443 >/dev/null 2>&1 &"'; sleep 3
    bin/trustgate exec -url "$MCP" -workload csv-stats -input testdata/transactions.csv -args amount,supplier -out $D/plain.json >/dev/null
    sleep 2; $SSH 'sudo pkill tcpdump; sleep 1'
    echo "same job UNSEALED, plaintext words seen by the parent: $($SSH 'sudo strings /tmp/demo-plain.pcap | grep -ciE "acme|beta|gamma|anomalies|stddev"')"

    step "11. The parent tries to decrypt with its own credentials (no enclave attestation)"
    $SSH 'aws kms decrypt --region ap-south-1 --ciphertext-blob fileb://<(base64 -d ~/ct.b64) --query Plaintext --output text' 2>&1 | cut -c1-260
  fi
fi

bold "done"
[ "$FAILED" = 0 ] && echo "every attack was refused and every check behaved as expected" || { echo "SOMETHING BEHAVED UNEXPECTEDLY"; exit 1; }
