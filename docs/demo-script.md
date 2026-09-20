# Demo script and runbook (about 7 minutes)

Everything in the demo has been run on a real enclave; see `docs/evidence.md` for the recorded outputs. The Bedrock gateway is **not built**, so it is not part of this demo. Say "next" for it, and do not show it.

The pitch in one line: **"Don't trust the server. Verify the execution."** And the honest limit, said out loud: **the receipt proves what ran and where, not that the answer is correct.**

## Before you start (pre-flight, 10 minutes)

On the instance (start it in the console first; the IP changes on every start):

1. Security group `trustgate-parent`: SSH and 8443 sources set to **My IP** (your IP may have changed).
2. `ssh` in, then `~/start-trustgate.sh ~/agent.eif` (or whichever image you are demoing). Expect `RUNNING flags=NONE` and `"mode": "nitro"`.
3. Note the enclave PCR0 it prints. Export it on the laptop: `export PCR=<PCR0>`.
4. If you will show the confidential section: the KMS key policy must contain this image's PCR0 and the data owner's `GenerateDataKey` statement, and the owner's access keys must be set in the laptop terminal (`set -x AWS_ACCESS_KEY_ID ...` in fish). Check with `kms-test` on the instance (see `.agent/reopen.md`).

On the laptop:

```bash
export TRUSTGATE_URL=http://<INSTANCE_IP>:8443
export PCR=<PCR0>
# dry run of everything except narration, ends with "every attack was refused ...":
PAUSE=0 DEMO_SEALED=1 scripts/demo-enclave.sh
```

The script's preflight refuses to run if the server is not `mode=nitro` with your pinned PCR0, so a wrong or stale build fails before you are on camera. **Run the dry run once before recording.**

The client registrations point at the instance's *current* IP, so update them after every restart:

```bash
claude mcp remove trustgate-enclave; claude mcp add --transport http trustgate-enclave http://<INSTANCE_IP>:8443/mcp
# opencode: edit the "trustgate-enclave" url in ./opencode.json
```

Start a **new** `claude` or `opencode` session in the repo folder after changing them; running sessions do not pick up new servers.

## The flow

| Time | Show | Say |
|---|---|---|
| 0:00 | Title slide or the README top | "Agents can call tools, but when a tool runs remote code we are mostly trusting the machine that ran it. TrustGate makes execution verifiable." |
| 0:30 | **Agent demo.** In Claude Code or opencode (in the repo folder), paste the agent prompt below. Show the tool calls, the result, and the verification | "The agent doesn't know about enclaves. It calls one MCP tool and gets the answer plus a signed receipt." |
| 1:45 | **Independent verification** (script steps 1 to 3): `exec`, `verify` with `-measurement $PCR`, `replay` | "Now I don't trust the agent or the server. On my own machine I check the receipt: the signature, that the signing key is bound to a real AWS Nitro attestation document verified against the AWS root, and that the enclave measurement is the one I pinned. Then I replay the job here and get the same output hash." |
| 2:40 | *Optional:* the **independent verifier** in a browser (`web/verify.html` with `sam local start-api` running): paste the receipt and PCR0, see five ticks; change one character, see a cross | "A different machine, not the server that ran the job, checks it. Same answer." |
| 3:00 | **Tamper** (script steps 4 to 6): one input byte, an edited receipt, a wrong measurement | "This is the point. Change one byte of the input: replay fails. Edit the receipt: the signature fails. Pin a different enclave: rejected." |
| 4:00 | **Confidential job** (script steps 8 and 9, or the recorded capture): show `sealed.json` (ciphertext), the decrypted result, verify and replay with the owner's salts, then the re-target attack refused | "The data owner encrypts on their machine. The server operator only ever handles ciphertext, and the ciphertext can only be used for this exact job. The enclave gets the key from KMS only because its measurement matches the key policy." |
| 5:15 | **Parent-side proof** (script steps 10 and 11 if you pass `SSH_TARGET`): packet capture 0 hits vs plaintext hits for the same job unsealed; the parent's own decrypt gets `AccessDenied` | "This is a capture on the host operator's own instance. Sealed job: nothing readable. Same job unsealed: the results in the clear. And with the same credentials, without attestation, KMS refuses." |
| 6:15 | Recorded proof of the modified-image refusal (`docs/evidence.md` section 2c), or say it | "Even a one-flag change to the enclave image changes its measurement, and KMS refuses to give it the key." |
| 6:40 | Honest limits slide | "The receipt proves what code ran and where. It does not prove the algorithm is correct. AWS Nitro remains the trust root. The host still sees metadata such as timing and sizes. Next: a Bedrock gateway that applies attested privacy policies to sensitive prompts." |

## Agent prompt (paste this)

Pin your real PCR0 in place of `<PCR0>`.

```
Use only the trustgate-enclave MCP tools. (1) Call get_attestation and tell me the mode and measurement. (2) Run the csv-stats workload on this CSV with args value and group:
group,value
a,10
a,12
b,11
b,13
a,11
b,12
a,9
b,10
a,10
b,11
a,12
b,9
c,5000
Report the per-group sums and any anomaly rows. (3) Call verify_receipt with the receipt_id from step 2 and expected_measurement set to <PCR0>. State precisely whether every check passed, what kind of attestation was used, and whether the measurement matched. Be brief.
```

Expected (recorded for both Claude Code and opencode): mode `nitro`, sums a=64 b=66 c=5000, anomaly at row 14, all 5 checks passed with a real Nitro attestation and the measurement matching.

Say when it lands: "That check ran on the server itself, so it is a convenience. The independent check is the CLI, which I run next."

## Running the terminal part

`PAUSE=1` (default) waits for Enter before each step, so you narrate at your own pace. Sections that need AWS credentials or SSH are skipped unless you pass `DEMO_SEALED=1` and `SSH_TARGET=ec2-user@<INSTANCE_IP> SSH_KEY=<key.pem>`.

```bash
DEMO_SEALED=1 SSH_TARGET=ec2-user@<INSTANCE_IP> SSH_KEY=<key.pem> scripts/demo-enclave.sh
```

The parent-side steps 10 and 11 (packet capture, direct KMS decrypt) have only been run by hand so far, not via this script over SSH. Rehearse them once; if anything misbehaves, run the same commands from `.agent/setup.md` B12 manually or show the recorded captures in `docs/evidence.md`.

## Recording tips

- Record with any screen recorder that also captures your microphone (OBS Studio works everywhere). Record narration and screen together in one take of 7 minutes; rehearse first.
- Use a large terminal font, a clean prompt, and clear the scrollback before starting.
- **Keep secrets off screen:** no `.pem` filename or path in view, no AWS keys (set them before recording and clear the screen), no `.env`. Instance IPs are fine but you can blur them. Use `<INSTANCE_IP>` placeholders in slides.
- The `.demo/` folder holds the demo's keys and salts; it is git-ignored.
- Record the agent part in its own take; model output varies a little run to run and you may want to re-record only that segment.

## If something breaks on the day

| Problem | Fix |
|---|---|
| Script preflight says wrong measurement or mode | The enclave is not the build you pinned. Re-run `~/start-trustgate.sh ~/<image>.eif` and re-export `PCR` |
| `exec` or `curl` hangs | Security group rule for 8443 no longer matches your IP (or the IP changed after a restart) |
| Agent says it cannot connect | Client still points at the old IP; update it (above) and start a fresh session |
| Confidential steps fail with a KMS error | Key policy PCR0 does not equal the running image, or the owner keys are not set in this terminal; check `~/start-trustgate.sh` output `credentials pushed to enclave` |
| Instance or AWS is unavailable | Run the whole flow locally: `MODE=dev TRUSTGATE_URL=http://localhost:18080 scripts/demo-enclave.sh` (say clearly that it is insecure dev mode), and show the recorded real-enclave outputs in `docs/evidence.md` |
| An agent invents a claim | Do not paraphrase for it: "the receipt proves what ran and where, not correctness" |

## Claims to avoid (from the project's own rules)

- "Proves the answer is correct." "Makes AWS untrusted." "Nitro guarantees privacy against everyone." "Nobody else does MCP plus WASM." "DPDP compliant." "Zero trust."
- Prefer: "attested execution", "signed execution receipts", "replayable deterministic workloads", "operator-isolated computation", "capability-constrained WASM".
- Prior art to mention if asked: Microsoft Wassette (MCP plus WASM), AWS AgentCore Code Interpreter. The difference is the attested environment, the receipt, and replay.
