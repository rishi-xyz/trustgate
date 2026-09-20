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
| E (reproducible build) | `1c680df50a18ba46d3bce7af9d63d653335593a788d25c624aa378c9c9e782072408baf0a836f01d4a6481dc243a030e` | section 7 |
| F (production, hardened server) | `81800d9fe493807540feae3c0d325abf185bde59e695ebe98b58a2f8c630e6997b26e0546eb9ed65d3c816ef1bec47d3` | section 10 |

Builds A to D were made before builds were reproducible: rebuilding the same source gave a different PCR0 each time, which is why each of those sections pins its own build. Build E onwards is reproducible (section 7).

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

## 7. Reproducible builds, and the full guided run (build E)

**The problem.** Rebuilding the same source gave a different enclave measurement every time, which meant the KMS key policy had to be edited after every rebuild, and it undermined the idea of a published expected measurement. Rehearsing the demo exposed one cause: Go stamps the git revision into every binary, so the same source produced a different WASM hash at each commit, and `replay` failed against a module built later with `workload hash: supplied wasm hashes to sha256:cd36d478…, receipt says sha256:8fbb22ec…`.

**The fixes:**
- WASM and server builds use `-buildvcs=false -trimpath`. Checked: the same source gives the same WASM hash at HEAD and three commits back (`20709cdb…`); the default build gave `cd36d478…` at HEAD and `0a2e6839…` three commits back.
- The enclave image pins its base images by digest, normalises every file's timestamp in the build stage, and copies the staged tree to `/` in one step (copying a directory to a new path made Docker stamp it with the build time).
- Locally, two `--no-cache` builds with touched inputs produce identical image layers. This was found by inspecting layer contents: the binary and key layers matched and only the `registry/` directory entry's timestamp differed, which the last change removed.

**The check on the parent instance** (`make eif-check` builds the enclave image from scratch twice, the second time after touching the inputs as a fresh tarball would, and compares PCR0):

```
$ make eif-check
[... two from-scratch docker builds and two nitro-cli build-enclave runs ...]
PCR0 build 1: 1c680df50a18ba46d3bce7af9d63d653335593a788d25c624aa378c9c9e782072408baf0a836f01d4a6481dc243a030e
PCR0 build 2: 1c680df50a18ba46d3bce7af9d63d653335593a788d25c624aa378c9c9e782072408baf0a836f01d4a6481dc243a030e
REPRODUCIBLE: same source, same measurement
```

Docker's own image IDs differed between the two builds (`afcf11c2…` and `08e7d2a3…`); the measurement did not. The KMS key policy was updated once, for this measurement, and the attested decrypt then succeeded:

```
$ bin/trustgate-parent kms-test -ciphertext-file ~/ct.b64 -region ap-south-1
{
  "ok": true,
  "plaintext_sha256": "c735232a670453957009e8341e5b9be106b2f12fdbcc1028b00733a537b84a43",
  "plaintext_len": 21,
  "measurement": "1c680df50a18ba46d3bce7af9d63d653335593a788d25c624aa378c9c9e782072408baf0a836f01d4a6481dc243a030e"
}
```

**The guided demo script against build E**, run from the laptop with the measurement pinned (`scripts/demo-enclave.sh`, non-confidential sections; output filtered to the check lines):

```
server: mode=nitro measurement=1c680df50a18ba46d3bce7af9d63d653…
== 2. Anyone can verify it independently: signature, real Nitro attestation, key binding, pinned measurement
✓ attestation document: nitro attestation verified
✓ enclave measurement: matches pinned 1c680df5…a030e
EXECUTION VERIFIED (proves what ran and where, not that the result is correct)
== 3. ...and replay it on this machine: same code + same input = same output hash
✓ input hash: supplied input matches receipt
✓ replay output hash: replayed output hash matches receipt
EXECUTION VERIFIED (proves what ran and where, not that the result is correct)
== 4. Attack: change one byte of the input, then replay
VERIFICATION FAILED
   ^ refused, as expected
== 5. Attack: edit the receipt (overwrite the output hash), then verify
VERIFICATION FAILED
   ^ refused, as expected
== 6. Attack: verify against the wrong enclave measurement
VERIFICATION FAILED
   ^ refused, as expected
== 7. Binary input and a long-running async job
[... both succeed ...]
every attack was refused and every check behaved as expected
```

The replay in step 3 used a `.wasm` **built independently on the laptop** (`20709cdb…`); it matched the module baked into the enclave image, which is the end-to-end proof that the reproducible-build fix works.

**What this does and does not establish.** Reproducibility was confirmed on one parent instance, for one source tree, with the base images pinned by digest. Someone rebuilding independently needs the same source, the same pinned base images and the same Nitro CLI version to expect the same PCR0; a different Nitro CLI or kernel image could change it. This was not tested.

## 8. Independent verifier on Lambda, tested with SAM Local

`verify_receipt` on the server is a convenience check, since the server that produced the receipt checks it (section 6). `lambda/verifier` is a Lambda that verifies a receipt from somewhere else, using the same verification code, and refuses software-only dev receipts. It was built and run **locally with SAM Local** (a Lambda container on the laptop); nothing was deployed to AWS.

Build and run (the binary is built static with `CGO_ENABLED=0`; the first build was dynamically linked against the laptop's newer glibc, which the Lambda AL2023 image may not have):

```
$ cd lambda && CGO_ENABLED=0 sam build
Build Succeeded
$ file .aws-sam/build/VerifierFunction/bootstrap
[...] ELF 64-bit LSB executable, x86-64, statically linked
$ sam local start-api -p 3000
Mounting VerifierFunction at http://127.0.0.1:3000/{proxy+} [...]
```

Tests through HTTP, using a **real receipt from the real enclave** (build E) as the input. Output filtered to the check names and status:

```
== valid receipt, pinned to the enclave's PCR0
{"verified":true,"checks":[{"name":"receipt signature","status":"pass"},{"name":"attestation reference","status":"pass"},{"name":"attestation document","status":"pass"},{"name":"signing key binding","status":"pass"},{"name":"enclave measurement","status":"pass"}]}

== wrong pinned measurement
{"verified":false,"failed":["enclave measurement"]}

== edited receipt (output hash overwritten)
{"verified":false,"failed":["receipt signature"]}

== garbage body
HTTP 400
```

The one-file page `web/verify.html` was driven in headless Chrome against the same SAM Local endpoint (fill in the receipt and pin, click Verify, read the result):

```
valid+pin => Verified: what ran and where is confirmed | ok | pass:receipt signature, pass:attestation reference, pass:attestation document, pass:signing key binding, pass:enclave measurement
edited    => Verification FAILED | bad | fail:receipt signature, pass:attestation reference, pass:attestation document, pass:signing key binding, pass:enclave measurement
not json  => error message shown: "The receipt is not valid JSON."
```

Unit tests in `lambda/verifier` (same fixture, no network): valid receipt passes all 5 checks; an unpinned request passes with the measurement check reported as *skipped*, not passed; a wrong pin, a forged receipt, a corrupted attestation document and a software-only dev receipt are all refused; oversized and malformed requests return 413 and 400.

**No change to the enclave.** The enclave server binary, built with the reproducible flags, has the same SHA-256 before and after this work (`ad38a76a…cd377a`), so the enclave image, its PCR0 and the KMS key policy are unaffected.

**Limits.** The verifier checks signature, attestation, key binding and a pinned measurement; it does not replay the workload (that needs the `.wasm`). It is only as independent as where you run it and what measurement you pin. The test receipt embeds the EC2 instance and enclave IDs, as every Nitro attestation does.

## 9. A Strands agent (AWS Strands Agents SDK) using the MCP tools

`agents/strands_demo.py` is an agent written with AWS Strands Agents that connects to TrustGate with Strands' own MCP client (streamable HTTP), lists the tools, runs a job and verifies the receipt by `receipt_id`. Strands 1.56.0 and mcp 1.30.0 were used. The `--check` mode exercises this whole path **without any model or AWS credentials**, so it tests the MCP integration itself.

Against a local dev server (dev-mode attestation, insecure, so no measurement was pinned and that check is skipped):

```
$ agents/.venv/bin/python agents/strands_demo.py --url http://localhost:18080/mcp --check
tools: cancel_job, execute, execute_async, get_attestation, job_result, job_status, list_workloads, replay, verify_receipt
mode: dev | measurement: c8138a8cbbd524c62a4b513a5958100d...
execute: success | receipt_id: boot-9341e314-1
  [pass] receipt signature
  [pass] attestation reference
  [pass] attestation document
  [pass] signing key binding
  [skip] enclave measurement
verified: True
```

Against the **real enclave** (build E) with its PCR0 pinned:

```
$ agents/.venv/bin/python agents/strands_demo.py --url http://<INSTANCE_IP>:8443/mcp --pcr 1c680df5…a030e --check
tools: cancel_job, execute, execute_async, get_attestation, job_result, job_status, list_workloads, replay, verify_receipt
mode: nitro | measurement: 1c680df50a18ba46d3bce7af9d63d653...
execute: success | receipt_id: boot-c89ee9b5-7
  [pass] receipt signature
  [pass] attestation reference
  [pass] attestation document
  [pass] signing key binding
  [pass] enclave measurement
verified: True
```

A problem found on the way: the Strands documentation's example imports `streamablehttp_client` from `mcp.client.streamable_http`, but the newest `mcp` (2.1.1) renamed it and moved headers into an httpx client object, so the import failed. Strands itself accepts `mcp>=1.23,<2.2`; `agents/requirements.txt` pins `mcp<2`.

**Not yet run:** the model-driven agent (Bedrock). It needs Bedrock model access and an IAM key for this account; the steps are in `agents/README.md`. Until it is run, what is shown here is that a Strands agent's MCP client works against TrustGate, not that a Bedrock-backed model drives it well.

## 10. The public endpoint (build F)

The enclave is reachable at **`https://trustmcp.rishixyz.com/mcp`** with no login, so judges can use it themselves. Path: Cloudflare (TLS, rate limit, adds a secret header) to the parent instance over HTTPS (Cloudflare origin certificate, "Full (strict)") to nginx (accepts only Cloudflare's published addresses that also carry the secret header, body cap, per-visitor limit) to a vsock forwarder to the enclave. Build F is the hardened server: stateless MCP with JSON responses, two workers, a 10 s queue wait then a "server busy" error, a 4 MiB body cap, and a shared compiled-module cache (a call went from about 720 ms to about 25 ms). `docs/production.md` is the runbook.

**Why Cloudflare and not CloudFront.** The first design used CloudFront and AWS WAF (`infra/edge-us-east-1.yaml`, still in the repo, lints clean). AWS refused to create the distribution:

```
Resource handler returned message: "Access denied for operation 'AWS::CloudFront::Distribution: Your account must be verified before you can add new CloudFront resources. To verify your account, please contact AWS Support [...]' (Service: CloudFront, Status Code: 403 [...]) HandlerErrorCode: AccessDenied)
```

That is an account-level block, not a template error (the WAF web ACL in the same stack was created before it). Cloudflare, which already hosted the domain, replaced it.

### Resilience, on the real instance

```
# kill the enclave on purpose
$ sudo nitro-cli terminate-enclave --all
[... 8 x "still down" ...]
healthy again after ~90 seconds        # loop counter; the real time from the crash was about 100 to 110 s
$ sudo journalctl -u trustgate-watchdog ...
watchdog.sh: trustgate-watchdog: health check failed (3/3)
watchdog.sh: trustgate-watchdog: restarting the enclave
$ curl -s http://127.0.0.1:8444/.well-known/trustgate | jq -c '{mode, measurement}'
{"mode":"nitro","measurement":"81800d9f…c3d816ef1bec47d3"}
enclave RUNNING flags=NONE

# reboot the instance, then, without starting anything by hand:
$ uptime -p
up 10 minutes
$ systemctl is-active nitro-enclaves-allocator docker trustgate-enclave trustgate-forwarder nginx trustgate-watchdog.timer
active  (six times)
$ nitro-cli describe-enclaves | jq -r '.[0] | "\(.EnclaveName) \(.State) flags=\(.Flags)"'
enclave RUNNING flags=NONE
$ curl -s http://127.0.0.1:8444/healthz
{"status":"ok","uptime_seconds":647,"workers":2,"in_flight":0,"queued":0,"executed":0,"rejected_busy":0}
```

A crash costs roughly a two-minute outage; a reboot brings the whole stack back on its own.

### The origin cannot be used except through Cloudflare

```
$ curl -sk -o /dev/null -w 'direct to origin: HTTP %{http_code}\n' https://<ORIGIN_IP>/healthz
direct to origin: HTTP 403
```

Direct requests fail because the peer is not a Cloudflare address, even with the right secret and a spoofed `CF-Connecting-IP` (checked by `parent/test-nginx.sh`, which runs the real nginx configuration in Docker with 22 checks).

### Through the public URL

```
$ curl -s https://trustmcp.rishixyz.com/.well-known/trustgate | jq '{mode, measurement}'
{ "mode": "nitro", "measurement": "81800d9fe493807540feae3c0d325abf185bde59e695ebe98b58a2f8c630e6997b26e0546eb9ed65d3c816ef1bec47d3" }
$ curl -s https://trustmcp.rishixyz.com/healthz
{"status":"ok","uptime_seconds":2116,"workers":2,"in_flight":0,"queued":0,"executed":0,"rejected_busy":0}
```

The Go CLI, then independent verification pinned to the measurement:

```
$ trustgate exec -url https://trustmcp.rishixyz.com/mcp -workload csv-stats -input testdata/transactions.csv -args amount,supplier
status: success
{"column":"amount","count":15,"sum":51405.35,[...]"anomalies":[{"row":16,"value":50000,"z":3.7416571662382503}]}
$ trustgate verify pub.json -measurement 81800d9f…c3d816ef1bec47d3
✓ enclave measurement: matches pinned 81800d9f…
EXECUTION VERIFIED (proves what ran and where, not that the result is correct)
```

The Strands MCP client (`--check`), pinned:

```
mode: nitro | measurement: 81800d9fe493807540feae3c0d325abf...
execute: success | receipt_id: boot-c9540471-2
  [pass] receipt signature    [pass] attestation reference    [pass] attestation document
  [pass] signing key binding  [pass] enclave measurement
verified: True
```

The guided demo script (`scripts/demo-enclave.sh`, non-confidential sections), including replay on this machine with a module built on the laptop and all three tamper attacks:

```
== 3. ...and replay it on this machine
✓ replay output hash: replayed output hash matches receipt
== 4. Attack: change one byte of the input, then replay      VERIFICATION FAILED   ^ refused, as expected
== 5. Attack: edit the receipt (overwrite the output hash)   VERIFICATION FAILED   ^ refused, as expected
== 6. Attack: verify against the wrong enclave measurement   VERIFICATION FAILED   ^ refused, as expected
== 7. Binary input and a long-running async job              (both succeed)
every attack was refused and every check behaved as expected
```

### Real agents against the public URL

The same prompt (get the attestation, run `csv-stats` on a 13-row CSV with one outlier, verify the receipt by id with the measurement pinned) with **Claude Code** and with **opencode**; both reported mode `nitro`, sums a=64 b=66 c=5000, the anomaly at row 14, all five checks passing with a real Nitro attestation, and the measurement matching:

```
Claude Code:  verify_receipt: verified: true, and all 5 checks passed [...] a real AWS Nitro Enclaves attestation,
              not a simulated one. The measurement matched your expected value exactly.
opencode:     Receipt verification: verified=true, all 5 checks passed [...] Attestation was Nitro and the measurement matched.
```

### Behaviour under abuse, from one IP

```
# 300 requests, 30 in parallel, to /healthz through Cloudflare
     99 200     201 429
# 15 seconds later
HTTP 200

# 8 simultaneous CPU-heavy jobs (primes below 60,000,000) with 2 workers and a 10 s queue wait
      6 error: execute: server busy: all workers are in use, retry in a few seconds
      2 status: success
# afterwards
{"status":"ok","uptime_seconds":2310,"workers":2,"in_flight":0,"queued":0,"executed":9,"rejected_busy":6}
```

The rate limit (100 requests per 10 seconds per IP on Cloudflare's free plan) blocked the flood and recovered within seconds; the worker cap turned an overload into clear, retryable errors and the enclave stayed healthy. Note the trade-off: under a burst of heavy jobs most callers are told to retry. That is intended, and the limit of two workers is what protects the enclave.

### Problems found on the way (kept for honesty)

- The installer failed on the instance twice with problems my local tests could not show: Amazon Linux 2023's `curl-minimal` conflicts with a package named `curl`, and nginx's default `map` bucket is too small for a real 64-character secret (my tests had used a short one). Both are fixed, and `parent/test-nginx.sh` now tests with a real-length secret and the real Cloudflare address ranges.
- That test suite found two of my own bugs before they reached the instance: a "self-signed?" check that compared `subject=` text to `issuer=` text (never equal), and a miscount caused by Cloudflare's files having no trailing newline.
- An installer run that reused an old script (an empty tarball was shipped because the command ran in the wrong folder) was caught because its output text was the old wording.
- The CloudFront block above.

### What is not covered

Confidential (sealed) jobs are switched off on the public endpoint: the enclave holds no AWS credentials there, so a stranger cannot make it call KMS. They were demonstrated separately on a private endpoint (sections 3 and 6). The KMS key policy still names the measurement of an earlier build, so a private confidential window on this build needs the policy updated first.

## 11. What this shows, and what it does not

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
- Reproducible enclave builds were confirmed on one machine with pinned inputs (section 7); independent rebuilds by others with a different toolchain version were not tested.
- The enclave's memory contents were not attacked directly; the isolation property rests on AWS's documented Nitro guarantees.
