# TrustGate

A verifiable remote execution environment for AI agents: attested compute with signed proof receipts. An MCP agent submits an approved WebAssembly workload; it runs under deny-by-default capabilities and resource limits inside an isolated, measured, attested environment; the agent gets the result plus a signed receipt that can be independently verified and, for deterministic workloads, replayed.

"Trustless" here means you check a receipt instead of trusting the host or the agent's word. AWS Nitro remains the root of trust.

> **Proof of execution and environment, not proof of correctness.**

## The execution environment

The environment is what makes a receipt worth checking:

- **Isolated:** the job runs in wazero inside an AWS Nitro Enclave; the parent instance cannot look inside.
- **Measured:** the enclave image has a measurement (PCR0). Any change to the image changes it.
- **Attested:** AWS signs an attestation document naming the image that is running. The receipt-signing key is bound to that document.

A receipt is the proof that a given job ran in that environment.

## Status

Two modes, same code:

- **`-mode dev`**: local, software attestation, no hardware isolation. Insecure by design; receipts are labelled `dev` and the verifier rejects them unless `-allow-dev` is passed.
- **`-mode nitro`**: runs inside an AWS Nitro Enclave. Verified on real hardware:
  - the receipt-signing key is bound to a real Nitro attestation document that verifies against the AWS root CA;
  - edited receipts, changed inputs and wrong pinned measurements fail verification;
  - AWS KMS releases a secret only to the enclave with the exact measured image; the parent instance's own credentials and a modified image are both denied;
  - confidential jobs: an input sealed by a separate data-owner identity is unwrapped only by the attested enclave and the result comes back sealed. A packet capture on the parent instance of a sealed job contained none of the data or results, while the same job unsealed did; and a hostile parent that re-targets the ciphertext at another approved workload is refused.

Known gaps: WASM workload builds are reproducible (independent of the git revision, so a receipt can be replayed against a module built later), but whether an enclave image rebuilt from the same source gets the same PCR0 is not yet confirmed (until it is, every rebuild means updating the KMS key policy); transport to the MCP endpoint is plain HTTP.

TrustGate proves what code ran on which input in which environment. It does not prove the result is correct.

## MCP tools

| Tool | Purpose |
|---|---|
| `execute` | Run an approved workload; input as text (`input`) or raw bytes (`input_b64`); returns output plus a signed receipt bundle |
| `execute_async`, `job_status`, `job_result`, `cancel_job` | Long-running jobs: get a `job_id` immediately, poll, fetch the result, or cancel. Plain tools rather than the MCP Tasks extension (the Go SDK has no Tasks support yet) |
| `replay` | Re-run the workload in a receipt (by `receipt_id`) against the original input and compare the output hash (same server; replay on your own machine for independent evidence) |
| `execute` with `sealed_input` | **Confidential job**: input encrypted by the data owner, unwrapped only by the attested enclave, result sealed to the owner's key. See below |
| `verify_receipt` | Check signature, attestation, key binding and an optional pinned measurement. Takes the short `receipt_id` returned by `execute` (agents mis-copy the ~6 KB bundle) or the full bundle |
| `list_workloads`, `get_attestation` | Discover approved workloads and the server's attestation evidence |

## Confidential jobs

The data owner runs `trustgate seal`, which encrypts the input with a fresh data key (wrapped by KMS) and binds the ciphertext to one exact job: workload hash, arguments and the public key that may read the result. The enclave unwraps the data key with an attested KMS call, runs the job, and returns the output sealed to that key.

- The parent instance, the network and the forwarder only handle ciphertext.
- A hostile parent cannot point the ciphertext at a different approved workload, change the arguments, or redirect the result to its own key; each fails authentication.
- Receipt hashes for confidential jobs are salted with secrets only the owner holds, so small or guessable data cannot be brute-forced from the receipt. The owner replays with `trustgate replay -salts`.
- Arguments are authenticated but **not secret**. Put sensitive parameters in the sealed input.
- The parent still sees metadata: timing, sizes, which workload and arguments, and can delay or drop jobs.

Locally (`-mode dev`) a local key stands in for KMS; `make demo` shows the whole flow. On Nitro the data key is unwrapped by real KMS, gated by the enclave's measurement.

## Independent verifier (Lambda)

`verify_receipt` on the server is a convenience: the server that produced a receipt checks it. `lambda/verifier` is an AWS Lambda that does the same checks from somewhere else (signature, the AWS Nitro attestation document against the AWS root CA, key binding, and a pinned enclave measurement), and refuses dev-mode receipts. The `/verify` page of the website (`web/site`) is a front end for it: paste a receipt and the PCR0 you expect, and it shows a tick or cross per check.

Run it locally with SAM Local (nothing is deployed, everything runs in a local Lambda container):

```bash
cd lambda && CGO_ENABLED=0 sam build && sam local start-api      # http://127.0.0.1:3000
# then, in another terminal, run the site on a different port (SAM Local uses 3000) and open /verify:
#   cd web/site && npm install && npm run dev -- -p 4000      # http://localhost:4000/verify
curl -s -X POST localhost:3000/verify -H 'Content-Type: application/json' \
  -d "{\"receipt_bundle\": $(cat verifier/testdata/nitro-receipt.json), \"expected_measurement\": \"<PCR0>\"}"
```

Build with `CGO_ENABLED=0`, so the binary does not depend on the host's glibc. `sam deploy` (not done) would publish it as a public URL. The test fixture `lambda/verifier/testdata/nitro-receipt.json` is a real receipt from a real enclave run; like every Nitro attestation it contains the EC2 instance and enclave IDs, but no credentials or account ID.

## Try it

A public endpoint is running on a real AWS Nitro Enclave: **`https://trustmcp.rishixyz.com/mcp`** (MCP over HTTPS, no login; sample data only). Published enclave measurement (PCR0): `81800d9fe493807540feae3c0d325abf185bde59e695ebe98b58a2f8c630e6997b26e0546eb9ed65d3c816ef1bec47d3`. See `docs/judge-guide.md`.

## Running it for others

`docs/production.md` is the runbook for a public HTTPS deployment (CloudFront and WAF in front, nginx and systemd on the parent, a hardened stateless server in the enclave), with the limits stated plainly. `docs/judge-guide.md` is what to give someone who wants to try it.

## Quick start (local)

```bash
make test    # unit + e2e tests, including tamper and resource-limit attacks
make demo    # execute -> verify -> replay -> tamper, all local
```

See `.agent/setup.md` for MCP client setup and the AWS steps.

## Layout

- `cmd/trustgate-server` MCP server (Streamable HTTP at `/mcp`)
- `cmd/trustgate` publisher and verifier CLI: `keygen`, `publish`, `exec`, `verify`, `replay`
- `internal/runtime` wazero host, `deterministic-v1` profile
- `internal/registry` publisher-signed workload manifests
- `internal/receipts` canonical, hash-chained, Ed25519-signed receipts
- `internal/attest` dev and Nitro attestation providers and verification
- `workloads/` sample workloads (compiled to `wasip1`)
- `internal/kms`, `internal/control` attested KMS decrypt and the enclave control channel
- `cmd/vsock-forwarder`, `cmd/trustgate-parent` parent-side helpers for Nitro
- `Dockerfile.nitro` enclave image (registry and publisher key baked in, so they are part of the measurement)
- `lambda/verifier` independent receipt verifier (Lambda, tested with SAM Local)
- `web/site` Next.js website: landing page and the `/verify` page in front of the verifier. `npm run build` is the standard build (Vercel); `npm run build:static` writes plain files to `out/` for any static host (`STATIC_EXPORT=1`); `vercel.json` pins the Next.js framework preset
- `agents/` a Strands (AWS) agent that drives TrustGate over MCP with Bedrock; `--check` tests the MCP path without a model
- `tests/` end-to-end and attack tests
