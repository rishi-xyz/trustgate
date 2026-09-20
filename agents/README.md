# Strands demo agent

An agent built with [AWS Strands Agents](https://strandsagents.com) and Amazon Bedrock that calls TrustGate over MCP: it runs `csv-stats` in the enclave, then verifies the receipt with a pinned enclave measurement. It shows that any MCP-capable agent framework can use TrustGate.

## Setup

```bash
uv venv --python 3.12 agents/.venv
uv pip install --python agents/.venv/bin/python -r agents/requirements.txt
```

`requirements.txt` pins `mcp<2`: mcp 2.x moved HTTP headers into an httpx client object and the `streamablehttp_client(url, headers=...)` call used here (and in the Strands docs) is the 1.x form.

## 1. Test the MCP connection (no model, no AWS credentials)

```bash
# local dev server (insecure dev-mode attestation), see the top-level README to start one
agents/.venv/bin/python agents/strands_demo.py --url http://localhost:18080/mcp --check

# real enclave, pinned to its measurement
agents/.venv/bin/python agents/strands_demo.py --url http://<INSTANCE_IP>:8443/mcp --pcr <PCR0> --check
```

It lists the tools, reads the attestation, runs a job, and verifies the receipt by `receipt_id`. Against a real enclave every check, including the pinned measurement, should say `[pass]`.

## 2. Run the model-driven agent (needs Bedrock)

One-time console setup (`ap-south-1`, or your region):

1. **Bedrock, Model catalog:** enable access to a model. Anthropic models may ask for a one-time use-case form. Claude models in Mumbai are used through an **inference profile**; copy the exact ID from the console, because IDs change.
2. **IAM:** create a user, for example `trustgate-agent`, with this policy, and create an access key for it:
   ```json
   {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
     "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], "Resource": "*"}]}
   ```
   (`Resource: "*"` avoids having to list every regional model and inference-profile ARN; tighten it later.)
3. After the first call, check **Billing, Credits** to see whether Bedrock usage drew from credits.

Run it (fish shown; use `export` in bash). Do not paste the keys anywhere, and delete the key when you are done:

```fish
set -x AWS_ACCESS_KEY_ID <id>
set -x AWS_SECRET_ACCESS_KEY <secret>
set -x AWS_REGION ap-south-1
set -x BEDROCK_MODEL_ID <model or inference-profile id from the console>
agents/.venv/bin/python agents/strands_demo.py --url http://<INSTANCE_IP>:8443/mcp --pcr <PCR0>
```

Expected: the agent calls `get_attestation`, `execute` and `verify_receipt` and reports mode `nitro`, sums `acme` 718.55, `beta` 686.8, `gamma` 50000, the anomaly at row 16, all five checks passing, and the honest limit (the receipt shows what ran and where, not that the answer is correct). The agent's `verify_receipt` runs on the server that produced the receipt, so it is a convenience; the independent check is the `trustgate` CLI or `lambda/verifier`.
