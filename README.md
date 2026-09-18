# TrustGate

Attested compute for AI agents. An MCP agent submits an approved WebAssembly workload; it runs under deny-by-default capabilities and resource limits; the agent gets the result plus a signed receipt that can be independently verified and, for deterministic workloads, replayed.

> **Proof of execution and environment, not proof of correctness.**

## Status

Working locally in **insecure dev mode** (software attestation, no hardware isolation). AWS Nitro Enclave mode (`-mode nitro`) is implemented but not yet exercised on real hardware.

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
- `tests/` end-to-end and attack tests
