# TrustGate

Attested compute for AI agents. An MCP agent submits an approved WebAssembly workload; it runs under deny-by-default capabilities and resource limits; the agent gets the result plus a signed receipt that can be independently verified and, for deterministic workloads, replayed.

> **Proof of execution and environment, not proof of correctness.**

## Status

Two modes, same code:

- **`-mode dev`**: local, software attestation, no hardware isolation. Insecure by design; receipts are labelled `dev` and the verifier rejects them unless `-allow-dev` is passed.
- **`-mode nitro`**: runs inside an AWS Nitro Enclave. Verified on real hardware:
  - the receipt-signing key is bound to a real Nitro attestation document that verifies against the AWS root CA;
  - edited receipts, changed inputs and wrong pinned measurements fail verification;
  - AWS KMS releases a secret only to the enclave with the exact measured image; the parent instance's own credentials and a modified image are both denied;
  - confidential jobs: an input sealed by a separate data-owner identity is unwrapped only by the attested enclave and the result comes back sealed. A packet capture on the parent instance of a sealed job contained none of the data or results, while the same job unsealed did; and a hostile parent that re-targets the ciphertext at another approved workload is refused.

Known gaps: builds are not reproducible yet (every rebuild changes PCR0, so the KMS key policy must be updated), transport to the MCP endpoint is plain HTTP.

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
- `tests/` end-to-end and attack tests
