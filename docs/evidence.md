# TrustGate: evidence from real runs

Everything below was run by hand on a real AWS Nitro Enclave on 2026-09-20 (region `ap-south-1`) and the outputs are pasted as they were printed. Only three things were edited: the AWS account ID, the instance's public IP, and instance/request IDs, which are replaced by `<ACCOUNT_ID>`, `<INSTANCE_IP>`, `<INSTANCE_ID>` and `<REQUEST_ID>`. Long banners were trimmed, marked `[...]`.

> **Proof of execution and environment, not proof of correctness.** These runs show what code ran, on which input, inside which measured enclave. They do not show that a workload's algorithm is right.

## 0. Environment

| | |
|---|---|
| Parent | EC2 `m5.xlarge` (x86_64), Amazon Linux 2023 |
| Enclave tooling | Nitro CLI 1.5.0 |
| Enclave | 2 vCPU, 3072 MiB, started **without** `--debug-mode` (`Flags: NONE`), so PCRs are real |
| Runtime | wazero 1.12.0, profile `deterministic-v1` |
| KMS | symmetric customer-managed key, policy conditioned on the enclave image measurement |

Builds referenced (PCR0 is the SHA-384 measurement of the whole enclave image; any change to the image changes it):

| Build | PCR0 | Used in |
|---|---|---|
| A | `ac40e634654562022930a64e584106fe5e07ea23062282a839cedef696ee2af9e301425124aa6ceb4ed4ea29ec01da07` | section 1 |
| B | `c1d966a3dd3e17b190e2a719dc56ddad967ef94aa50e100aeee324fbe9b1e842da466a507fb2ed6a4c887f1f5f9ccb97` | section 2 |
| B-evil (deliberately modified) | `ffcbc3320ef1edb0ae85a9ac36fe9a39a863dce3d60322489155749eb32c42b9b995c516d1969520aa71e5c514bec594` | section 2 |
| C | `92de20fec5a521505d849c92cc4827e3ceb9c68bec6d09e98eedc1d50b3e224d09a34afb905822e6ac042bfe6607d2a4` | section 3 |
| D | `1321d0d4652b0c26ee5a51f3aa11b7f6584e780e23fa2a658a75d6c16c1992efe53bcba047e188f9cda6d7a01c8e74db` | section 6 |

The same source produces a different PCR0 on each rebuild (builds are not reproducible yet), which is why each section pins its own build.

## 1. Real Nitro attestation, verified off the instance (build A)

The enclave ran the server. From a laptop, a job was submitted over MCP, and the receipt was verified with **no dev flags**, pinned to the enclave's PCR0. The verifier checks the COSE_Sign1 attestation document against the AWS Nitro root CA.

Server evidence endpoint, queried on the instance:

```
$ curl -s localhost:8443/.well-known/trustgate | jq '{mode, measurement, warning, signer_pub}'
{
  "mode": "nitro",
  "measurement": "ac40e634654562022930a64e584106fe5e07ea23062282a839cedef696ee2af9e301425124aa6ceb4ed4ea29ec01da07",
  "warning": null,
  "signer_pub": "798c4fe481546e5051d73e2595a1a5346b334cbe622971fc6dd2aa2cac5d6190"
}
```

Job and verification, from the laptop:

```
$ bin/trustgate exec -url http://<INSTANCE_IP>:8443/mcp -workload csv-stats \
    -input testdata/transactions.csv -args amount,supplier -out receipt.json
status: success
{"column":"amount","count":15,"sum":51405.35,"mean":3427.023333333333,"min":90,"max":50000,"stddev":12447.152317134854,"groups":{"acme":718.55,"beta":686.8000000000001,"gamma":50000},"anomalies":[{"row":16,"value":50000,"z":3.7416571662382503}]}

receipt saved to receipt.json

$ bin/trustgate verify receipt.json -measurement ac40e634654562022930a64e584106fe5e07ea23062282a839cedef696ee2af9e301425124aa6ceb4ed4ea29ec01da07
✓ receipt signature: Ed25519 signature matches receipt contents
✓ attestation reference: attestation document matches the hash committed in the receipt
✓ attestation document: nitro attestation verified
✓ signing key binding: signing key is the one bound by the attestation document
✓ enclave measurement: matches pinned ac40e634654562022930a64e584106fe5e07ea23062282a839cedef696ee2af9e301425124aa6ceb4ed4ea29ec01da07

EXECUTION VERIFIED (proves what ran and where, not that the result is correct)
```

Replay on a different machine (the laptop), plus three attacks:

```
$ bin/trustgate replay receipt.json -measurement $PCR -wasm build/csv-stats.wasm -stdin testdata/transactions.csv
✓ receipt signature: Ed25519 signature matches receipt contents
✓ attestation reference: attestation document matches the hash committed in the receipt
✓ attestation document: nitro attestation verified
✓ signing key binding: signing key is the one bound by the attestation document
✓ enclave measurement: matches pinned ac40e634…da07
✓ workload hash: supplied wasm matches receipt code_sha256
✓ input hash: supplied input matches receipt
✓ replay output hash: replayed output hash matches receipt

EXECUTION VERIFIED (proves what ran and where, not that the result is correct)
```

```
# attack 1: one input byte changed (50000.00 -> 50000.01)
$ bin/trustgate replay receipt.json -measurement $PCR -wasm build/csv-stats.wasm -stdin /tmp/tampered.csv
[... first six checks pass ...]
✗ input hash: supplied input hashes to sha256:741e6fbc…6adc, receipt says sha256:3f808bd7…ac0f

VERIFICATION FAILED
```

```
# attack 2: receipt edited (output hash overwritten)
$ bin/trustgate verify /tmp/forged.json -measurement $PCR
✗ receipt signature: signature does not match receipt contents
✓ attestation reference: attestation document matches the hash committed in the receipt
✓ attestation document: nitro attestation verified
✓ signing key binding: signing key is the one bound by the attestation document
✓ enclave measurement: matches pinned ac40e634…da07

VERIFICATION FAILED
```

```
# attack 3: wrong pinned measurement
$ bin/trustgate verify receipt.json -measurement 00
✓ receipt signature: Ed25519 signature matches receipt contents
✓ attestation reference: attestation document matches the hash committed in the receipt
✓ attestation document: nitro attestation verified
✓ signing key binding: signing key is the one bound by the attestation document
✗ enclave measurement: attested ac40e634…da07, expected 00

VERIFICATION FAILED
```

## 2. KMS releases a secret only to the measured enclave (build B)

The KMS key policy allows `kms:Decrypt` for the instance's role **only** when `kms:RecipientAttestation:ImageSha384` equals the enclave's PCR0. There is deliberately no statement that lets any account principal (including administrators) decrypt without attestation.

Mechanism: the parent tool hands the enclave the role's temporary credentials and a ciphertext over a private vsock control port. The enclave puts an ephemeral RSA public key into a Nitro attestation document, calls KMS `Decrypt` with it as `Recipient` through the parent's `vsock-proxy`, and opens the response with the ephemeral private key. Only a SHA-256 of the plaintext leaves the enclave.

Expected plaintext hash (`printf 'trustgate-demo-secret' | sha256sum`): `c735232a670453957009e8341e5b9be106b2f12fdbcc1028b00733a537b84a43`

**2a. The measured enclave decrypts:**

```
$ bin/trustgate-parent kms-test -ciphertext-file ct.b64 -region ap-south-1
{
  "ok": true,
  "plaintext_sha256": "c735232a670453957009e8341e5b9be106b2f12fdbcc1028b00733a537b84a43",
  "plaintext_len": 21,
  "measurement": "c1d966a3dd3e17b190e2a719dc56ddad967ef94aa50e100aeee324fbe9b1e842da466a507fb2ed6a4c887f1f5f9ccb97"
}
```

**2b. Attack: the parent, with the same role credentials but no enclave attestation, tries to decrypt:**

```
$ aws kms decrypt --region ap-south-1 --ciphertext-blob fileb://<(base64 -d ct.b64) --query Plaintext --output text

An error occurred (AccessDeniedException) when calling the Decrypt operation: User: arn:aws:sts::<ACCOUNT_ID>:assumed-role/trustgate-parent-role/<INSTANCE_ID> is not authorized to perform: kms:Decrypt on resource: arn:aws:kms:ap-south-1:<ACCOUNT_ID>:key/<KEY_ID> because no resource-based policy allows the kms:Decrypt action
```

**2c. Attack: a slightly modified enclave image (one extra flag in the entrypoint) is a genuine, attested enclave with a different measurement:**

```
$ nitro-cli build-enclave --docker-uri trustgate:evil --output-file ~/evil.eif
"PCR0": "ffcbc3320ef1edb0ae85a9ac36fe9a39a863dce3d60322489155749eb32c42b9b995c516d1969520aa71e5c514bec594"

$ bin/trustgate-parent kms-test -ciphertext-file ct.b64 -region ap-south-1
{
  "ok": false,
  "measurement": "ffcbc3320ef1edb0ae85a9ac36fe9a39a863dce3d60322489155749eb32c42b9b995c516d1969520aa71e5c514bec594",
  "error": "kms decrypt: operation error KMS: Decrypt, https response error StatusCode: 400, RequestID: <REQUEST_ID>, api error AccessDeniedException: User: arn:aws:sts::<ACCOUNT_ID>:assumed-role/trustgate-parent-role/<INSTANCE_ID> is not authorized to perform: kms:Decrypt on resource: arn:aws:kms:ap-south-1:<ACCOUNT_ID>:key/<KEY_ID> because no resource-based policy allows the kms:Decrypt action"
}
```

**2d. Restoring the original image decrypts again** (same `good.eif`, unchanged PCR0):

```
$ nitro-cli run-enclave --cpu-count 2 --memory 3072 --eif-path ~/good.eif --enclave-cid 16
$ bin/trustgate-parent kms-test -ciphertext-file ct.b64 -region ap-south-1
{
  "ok": true,
  "plaintext_sha256": "c735232a670453957009e8341e5b9be106b2f12fdbcc1028b00733a537b84a43",
  "plaintext_len": 21,
  "measurement": "c1d966a3dd3e17b190e2a719dc56ddad967ef94aa50e100aeee324fbe9b1e842da466a507fb2ed6a4c887f1f5f9ccb97"
}
```

### Problems found along the way (kept for honesty)

- The first KMS attempt was denied because the PCR0 pasted into the key policy was truncated. The denial message is the same for "no attestation", "wrong measurement" and "policy typo", so the value has to be copied exactly (`jq -r .Measurements.PCR0`).
- After the policy was fixed, KMS allowed the call but decryption failed with `asn1: syntax error: indefinite length found (not DER)`. KMS returns BER, not DER. A BER-to-DER normaliser was added and tested against OpenSSL's streaming (BER) output before the successful run above.

## 3. Newer features on the real enclave (build C)

Enclave state and server evidence:

```
--- creds pusher
12:05:26 push failed: dial enclave control port: dial vsock vm(16):8081: connect: connection reset by peer
12:05:31 credentials pushed to enclave (measurement 92de20fec5a52150…)
--- enclave
new RUNNING flags=NONE
--- server
{
  "mode": "nitro",
  "measurement": "92de20fec5a521505d849c92cc4827e3ceb9c68bec6d09e98eedc1d50b3e224d09a34afb905822e6ac042bfe6607d2a4"
}
```

(The first push failed only because the enclave was still booting; the pusher retried after five seconds.)

The attested KMS check on this build:

```
$ bin/trustgate-parent kms-test -ciphertext-file ~/ct.b64 -region ap-south-1
{
  "ok": true,
  "plaintext_sha256": "c735232a670453957009e8341e5b9be106b2f12fdbcc1028b00733a537b84a43",
  "plaintext_len": 21,
  "measurement": "92de20fec5a521505d849c92cc4827e3ceb9c68bec6d09e98eedc1d50b3e224d09a34afb905822e6ac042bfe6607d2a4"
}
```

### 3a. Binary input (100,000 random bytes, not valid text)

```
$ bin/trustgate exec -url http://<INSTANCE_IP>:8443/mcp -workload hash-bytes -input /tmp/blob.bin -out blob.json
status: success
{"bytes":100000,"sha256":"7fdf5adfacc47b7bdb2adff7623da53195088e07d84c4d30e3d003ec84e007ed"}

$ sha256sum /tmp/blob.bin
7fdf5adfacc47b7bdb2adff7623da53195088e07d84c4d30e3d003ec84e007ed  /tmp/blob.bin
```

The enclave-side workload and the laptop agree on the hash. Verification and independent replay both pass (same checks as section 1, `EXECUTION VERIFIED`, including `✓ replay output hash: replayed output hash matches receipt`).

### 3b. Long-running async job

```
$ bin/trustgate exec -async -url http://<INSTANCE_IP>:8443/mcp -workload primes -args 60000000 -out async.json
job 73759e416361213f submitted
  status: running
  status: succeeded
status: success
{"count":3562115,"largest":59999999,"limit":60000000}

receipt saved to async.json
```

3,562,115 is the known number of primes below 60,000,000. `trustgate verify async.json -measurement 92de20fe…a2a4` passes with real Nitro attestation.

### 3c. Confidential job: encrypted input, sealed result

Roles: a separate data-owner AWS identity (`trustgate-owner`, allowed only `kms:GenerateDataKey`, not decrypt) seals the input on the laptop; the parent instance only relays ciphertext; the enclave unwraps the data key through attested KMS and returns the result sealed to a key only the owner holds. The ciphertext is bound to one workload hash, one argument list and one result key.

```
$ bin/trustgate seal -url http://<INSTANCE_IP>:8443/mcp -workload csv-stats -args amount,supplier \
    -input testdata/transactions.csv -out sealed.json -recipient recipient.key \
    -kms aws:alias/trustgate-demo -region ap-south-1
sealed 259 bytes for sha256:8bd26420fbfb31edebcef71a93e7ff1e155f3c536e53abf0fdd7095996e4f28e (args [amount supplier])
  -> sealed.json (safe to hand to an untrusted parent)
  -> sealed.json.meta (private: contains the input salt)

$ bin/trustgate exec -url http://<INSTANCE_IP>:8443/mcp -workload csv-stats -sealed sealed.json -out conf.json
status: success
(result is sealed: the server and any relay only saw ciphertext)
decrypted result:
{"column":"amount","count":15,"sum":51405.35,"mean":3427.023333333333,"min":90,"max":50000,"stddev":12447.152317134854,"groups":{"acme":718.55,"beta":686.8000000000001,"gamma":50000},"anomalies":[{"row":16,"value":50000,"z":3.7416571662382503}]}
salts saved to conf.json.salts.json (private)
receipt saved to conf.json
```

Verification with real attestation, then replay by the data owner using the secret salts (receipt commitments for confidential data are `sha256(salt || data)`, so the parent cannot brute-force small or guessable values from the receipt):

```
$ bin/trustgate verify conf.json -measurement 92de20fe…a2a4
✓ receipt signature: Ed25519 signature matches receipt contents
✓ attestation reference: attestation document matches the hash committed in the receipt
✓ attestation document: nitro attestation verified
✓ signing key binding: signing key is the one bound by the attestation document
✓ enclave measurement: matches pinned 92de20fe…a2a4

EXECUTION VERIFIED (proves what ran and where, not that the result is correct)

$ bin/trustgate replay conf.json -measurement 92de20fe…a2a4 -salts conf.json.salts.json \
    -wasm build/csv-stats.wasm -stdin testdata/transactions.csv
[... same five checks ...]
✓ workload hash: supplied wasm matches receipt code_sha256
✓ input hash: supplied input matches receipt
✓ replay output hash: replayed output hash matches receipt

EXECUTION VERIFIED (proves what ran and where, not that the result is correct)
```

### 3d. What the untrusted parent can see: packet captures on the parent instance

`tcpdump` ran **on the parent instance** (where the forwarder relays traffic) with one job per capture. `strings <pcap> | grep -ciE "acme|beta|gamma|anomalies|stddev"` counts lines with any data or result word.

```
# capture containing ONLY the sealed job
sealed job, plaintext hits:
0
$ sudo tcpdump -r /tmp/sealed.pcap 2>/dev/null | wc -l
49

# capture containing ONLY the same job sent unsealed (positive control)
48 packets captured
unsealed job, plaintext hits:
2
```

Zero hits in 49 packets for the sealed job, versus plaintext results visible for the unsealed job. (A first capture accidentally contained both jobs and showed hits; it was discarded and redone with one job per capture. The hits there were from the unsealed job.) Job arguments (`amount,supplier`) are visible in both cases on purpose: arguments are authenticated but not secret, so sensitive parameters belong in the sealed input.

### 3e. Attack: the parent re-targets the sealed input at a different approved workload

The parent holds `sealed.json` and can call `execute` itself. It points the ciphertext at `hash-bytes`, an approved workload that would reveal input if it echoed it:

```
$ bin/trustgate exec -url http://<INSTANCE_IP>:8443/mcp -workload hash-bytes -sealed sealed.json -out evil.json
error: execute: sealed input does not authenticate for this workload, arguments and recipient
```

The same rejection applies to changed arguments, a swapped result-recipient key, a flipped ciphertext bit, and data wrapped by a different KMS (covered by automated tests, section 4).

## 4. Automated tests (run locally, no AWS)

`make test` runs unit and end-to-end tests. The end-to-end tests run the real server and workloads over the MCP protocol:

| Area | Tests |
|---|---|
| Core flow | `TestExecuteVerifyReplay`, `TestChainAndDeterminism`, `TestVerifyReceiptTool` |
| Tamper and forgery | `TestAttackTamperedReceipt`, `TestAttackForgedSignerKey`, `TestAttackChangedInputReplay`, `TestAttackTamperedWasmReplay`, `TestRegistryRejects` |
| Resource limits | `TestLimits` (timeout and memory limits fail closed) |
| Binary input, async, replay | `TestBinaryInput`, `TestAsyncJob`, `TestAsyncFailureKeepsReceipt`, `TestCancelJob`, `TestReplayTool`, `TestReceiptByID` |
| Confidential path | `TestConfidentialJob`, `TestConfidentialNothingInTheClearOnTheWire` (with a positive control), `TestConfidentialParentAttacks`, `TestConfidentialDisabledWithoutKeys`, `TestConfidentialAsyncJob` |
| Crypto and encodings | seal/unseal round trips and binding tests, CMS/BER decryption checked against OpenSSL |

The suite also passed under the Go race detector for the async and confidential tests.

## 6. Real agent clients calling the real enclave (build D)

Claude Code 2.1.278 and opencode 1.18.31 were connected to the enclave's MCP endpoint, and asked in plain language to inspect the attestation, run a workload, and verify the receipt, pinned to the enclave's PCR0.

Setup used:

```
$ claude mcp add --transport http trustgate-enclave http://<INSTANCE_IP>:8443/mcp
```

```json
{ "mcp": { "trustgate-enclave": { "type": "remote", "url": "http://<INSTANCE_IP>:8443/mcp", "enabled": true } } }
```

Prompt given to both (the CSV has 13 rows with one large outlier):

> Use only the trustgate-enclave MCP tools. (1) Call get_attestation and tell me the mode and measurement. (2) Run the csv-stats workload on this CSV with args value and group: [CSV]. Report the per-group sums and any anomaly rows. (3) Call verify_receipt with the receipt_id from step 2 and expected_measurement set to 1321d0d4…92efe53bcba047e188f9cda6d7a01c8e74db. State precisely whether every check passed, what kind of attestation was used, and whether the measurement matched. Be brief.

### Claude Code

```
**1. Attestation:** the mode is `nitro`. The measurement is `1321d0d4652b0c26ee5a51f3aa11b7f6584e780e23fa2a658a75d6c16c1992efe53bcba047e188f9cda6d7a01c8e74db`.

**2. csv-stats:** I ran it as `csv-stats@1` with args `value` and `group`. The run succeeded and the receipt_id is `boot-b6aa5f7c-1`.
- **Per-group sums:** a = 64, b = 66, c = 5000.
- **Anomaly:** row 14 (the `c,5000` row), z ≈ 3.46. It is the only one flagged.
- **Overall:** count 13, sum 5130, mean ≈ 394.6, min 9, max 5000.

**3. verify_receipt:** `verified: true`, and all 5 checks passed:
- receipt signature
- attestation reference
- attestation document
- signing key binding
- enclave measurement

The attestation was a real AWS Nitro one (`nitro attestation verified`), not a local or simulated one. The measurement matched the value you pinned exactly.

The receipt shows what code ran on what input in that enclave. It does not show that the result is semantically correct.
```

### opencode (default model `big-pickle`)

```
> build · big-pickle
⚙ trustgate-enclave_get_attestation
⚙ trustgate-enclave_list_workloads
Mode: **nitro**. Measurement: `1321d0d4652b0c26ee5a51f3aa11b7f6584e780e23fa2a658a75d6c16c1992efe53bcba047e188f9cda6d7a01c8e74db`.
⚙ trustgate-enclave_execute {"workload":"csv-stats","args":["value","group"],"input":"group,value\na,10\n[...]\nc,5000"}
⚙ trustgate-enclave_verify_receipt {"receipt_id":"boot-b6aa5f7c-2","expected_measurement":"1321d0d4…92efe53bcba047e188f9cda6d7a01c8e74db"}
**1. Attestation:** mode `nitro`, measurement `1321d0d4…c8e74db`.
**2. csv-stats (`value`/`group`):** per-group sums — `a: 64`, `b: 66`, `c: 5000`. One anomaly: row 14, value `5000`, z = 3.464 (outlier in group `c`).
**3. Verify (`boot-b6aa5f7c-2`):** all 5 checks passed — receipt signature, attestation reference, attestation document (AWS **Nitro** attestation), signing-key binding, and pinned enclave measurement. Measurement **matched** exactly; `verified: true`.
```

### A failure this testing found, and the fix

The first run against the enclave (build C) did **not** complete verification. The agent got the correct result, then had to pass the whole receipt bundle to `verify_receipt`. A real Nitro attestation document is about 6 KB of base64 and the agent mis-copied it:

```
(3) verify_receipt: I could not complete it, so I can't say whether the checks passed.
- What happened: both attempts failed with `bad bundle: illegal base64 data at input byte 6024`.
```

The agent said so plainly instead of claiming success. The fix was server-side: `execute` and async jobs now return a short `receipt_id`, and `verify_receipt` and `replay` accept it instead of the full bundle (the bundle is still returned for independent verification). After the fix, both clients complete the flow above.

### Caveat on what these agent runs prove

`verify_receipt` called by an agent runs **on the same server** that produced the receipt, so it is a convenience check, not independent evidence. Independent verification is the CLI on a machine you control (sections 1 to 3), which checks the attestation against the AWS root CA itself.

## 7. What this shows, and what it does not

**Shown:**
- A workload's identity, input and output are committed in a signed receipt, and the signing key is bound to a real Nitro attestation document that anyone can verify against the AWS root.
- Any edit to the receipt, the input, or the pinned measurement makes verification fail.
- KMS gives the data key only to an enclave with the exact measured image; the parent's own credentials and a modified image are refused.
- For confidential jobs the parent instance and the network handled only ciphertext, and the ciphertext cannot be re-used for a different job.

**Not shown / limits:**
- A receipt is evidence of execution, not of correctness: an attested workload can still be wrong.
- AWS Nitro and its hardware and firmware remain part of the trust root.
- The parent still sees metadata: timing, sizes, which workload and arguments, and it can delay or drop jobs.
- The MCP endpoint had no authentication (only a security-group IP allowlist) and used plain HTTP during these runs; confidentiality of sealed jobs did not depend on either.
- Builds are not reproducible yet, so the key policy is updated after each rebuild.
- The enclave's memory contents were not attacked directly; the isolation property rests on AWS's documented Nitro guarantees.
