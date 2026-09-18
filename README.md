# TrustGate

Attested compute for AI agents. An MCP agent submits an approved WebAssembly workload; it runs under deny-by-default capabilities and resource limits; the agent gets the result plus a signed receipt that can be independently verified and, for deterministic workloads, replayed.

> **Proof of execution and environment, not proof of correctness.**

## Status

Two modes, same code:

- **`-mode dev`**: local, software attestation, no hardware isolation. Insecure by design; receipts are labelled `dev` and the verifier rejects them unless `-allow-dev` is passed.
- **`-mode nitro`**: runs inside an AWS Nitro Enclave. Verified on real hardware:
  - the receipt-signing key is bound to a real Nitro attestation document that verifies against the AWS root CA;
  - edited receipts, changed inputs and wrong pinned measurements fail verification;
  - AWS KMS releases a secret only to the enclave with the exact measured image; the parent instance's own credentials and a modified image are both denied.

Known gaps: builds are not reproducible yet (every rebuild changes PCR0, so the KMS key policy must be updated), transport to the MCP endpoint is plain HTTP, and encrypted job inputs are not yet wired into `execute`.

TrustGate proves what code ran on which input in which environment. It does not prove the result is correct.

## MCP tools

| Tool | Purpose |
|---|---|
| `execute` | Run an approved workload; input as text (`input`) or raw bytes (`input_b64`); returns output plus a signed receipt bundle |
| `execute_async`, `job_status`, `job_result`, `cancel_job` | Long-running jobs: get a `job_id` immediately, poll, fetch the result, or cancel. Plain tools rather than the MCP Tasks extension (the Go SDK has no Tasks support yet) |
| `replay` | Re-run the workload in a receipt against the original input and compare the output hash (same server; replay on your own machine for independent evidence) |
| `verify_receipt` | Check signature, attestation, key binding and an optional pinned measurement |
| `list_workloads`, `get_attestation` | Discover approved workloads and the server's attestation evidence |

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
