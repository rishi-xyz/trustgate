# TrustGate: judge guide

TrustGate lets an AI agent run an approved WebAssembly workload inside an **AWS Nitro Enclave** and get back a **signed receipt** that anyone can verify: which code ran, on which input, and in which attested enclave. The receipt proves what ran and where. It does **not** prove that the workload's answer is correct.

**Endpoint:** `https://trustmcp.rishixyz.com/mcp` (MCP over HTTPS, no login)
**Enclave measurement (PCR0), published:** `81800d9fe493807540feae3c0d325abf185bde59e695ebe98b58a2f8c630e6997b26e0546eb9ed65d3c816ef1bec47d3`

> **Please send sample data only.** Requests you send unsealed pass through CloudFront and the host that runs the enclave, and the host operator can read them. The confidential-job mode (encrypted inputs) is shown in `docs/evidence.md` and is switched off on this public endpoint.
> Requests are rate limited per IP, and only two jobs run at a time; if you see "server busy", retry in a few seconds.

## Try it with your agent

**Claude Code**

```bash
claude mcp add --transport http trustgate https://trustmcp.rishixyz.com/mcp
```

Start a new `claude` session and ask:

```
Use only the trustgate MCP tools. Call get_attestation and tell me the mode and measurement. Then run the csv-stats workload on this CSV with args value and group:
group,value
a,10
a,12
b,11
b,13
c,5000
and call verify_receipt with the receipt_id and expected_measurement set to 81800d9fe493807540feae3c0d325abf185bde59e695ebe98b58a2f8c630e6997b26e0546eb9ed65d3c816ef1bec47d3. Tell me exactly which checks passed and what this receipt does and does not prove.
```

Expected: mode `nitro`, sums a=22, b=24, c=5000, five checks passing (including the measurement), and an honest statement of the limits. (This exact flow was run through the public URL with Claude Code and opencode; see `docs/evidence.md` section 10.)

**opencode** (`opencode.json`)

```json
{ "mcp": { "trustgate": { "type": "remote", "url": "https://trustmcp.rishixyz.com/mcp", "enabled": true } } }
```

**Any MCP client**: it is a standard Streamable HTTP server (stateless, JSON responses). Tools: `get_attestation`, `list_workloads`, `execute`, `execute_async`, `job_status`, `job_result`, `cancel_job`, `verify_receipt`, `replay`.

## Verify a receipt yourself, without trusting the server

`verify_receipt` (the agent tool) is checked by the same server that produced the receipt, so treat it as a convenience. The independent check runs on your machine:

```bash
# get the CLI (checksums in SHA256SUMS): download trustgate-<os>-<arch> from the releases page, or build it
#   go install <REPO>/cmd/trustgate@latest      (or: make dist)
trustgate exec -url https://trustmcp.rishixyz.com/mcp -workload csv-stats -input data.csv -args amount,supplier -out receipt.json
trustgate verify receipt.json -measurement 81800d9fe493807540feae3c0d325abf185bde59e695ebe98b58a2f8c630e6997b26e0546eb9ed65d3c816ef1bec47d3
trustgate replay receipt.json -measurement 81800d9fe493807540feae3c0d325abf185bde59e695ebe98b58a2f8c630e6997b26e0546eb9ed65d3c816ef1bec47d3 -wasm csv-stats.wasm -stdin data.csv
```

`verify` checks the receipt signature, the AWS Nitro attestation document against the **AWS root certificate**, that the signing key is the one the attestation document names, and that the enclave measurement is the one you pinned. `replay` re-runs the workload on your machine and compares the output hash. Change one byte of the input, the receipt or the pinned measurement and it fails; `docs/evidence.md` shows this on a real enclave.

A browser version is in `web/verify.html` (with `lambda/verifier`, tested locally with SAM Local).

## Where the measurement comes from

The enclave image is built reproducibly (pinned base images, normalised timestamps, no git revision in binaries), so the same source gives the same PCR0. The published value `81800d9fe493807540feae3c0d325abf185bde59e695ebe98b58a2f8c630e6997b26e0546eb9ed65d3c816ef1bec47d3` is what `make eif-check` printed for this deployment. If you rebuild it yourself with the same Nitro CLI you should get the same value; a different toolchain version may not, and that was not tested.

## What this does not show

- That a workload is correct: an attested algorithm can still be wrong.
- That AWS is untrusted: Nitro and its hardware and firmware are the root of trust.
- Protection of unsealed traffic from the host operator, or of metadata (timing, sizes, which workload).
- High availability: this is a single instance.

## Problems

| Symptom | Likely cause |
|---|---|
| `server busy` | both workers are in use; retry shortly |
| HTTP 429 or 403 from the edge | you exceeded the per-IP rate limit; wait a few minutes |
| verification fails on the measurement | you pinned a different PCR0 than the one the enclave reports |
| it does not respond | the instance may be restarting; try again in two or three minutes |
