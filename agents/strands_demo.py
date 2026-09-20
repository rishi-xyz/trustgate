#!/usr/bin/env python3
"""A TrustGate demo agent built with AWS Strands Agents and Amazon Bedrock.

The agent connects to a TrustGate MCP endpoint, runs a workload in the enclave,
and verifies the signed receipt with a pinned enclave measurement. It shows that
any MCP-capable agent framework can use TrustGate, not just Claude Code.

  python agents/strands_demo.py --url http://localhost:18080/mcp                # dev server
  python agents/strands_demo.py --url http://<ip>:8443/mcp --pcr <PCR0>         # real enclave

Needs BEDROCK_MODEL_ID (copy the exact model or inference-profile ID from the
Bedrock console), AWS credentials that may call Bedrock, and AWS_REGION
(defaults to ap-south-1). Use --check to test only the MCP connection: it needs
no model and no AWS credentials.
"""
import argparse
import json
import os
import sys
from pathlib import Path

from mcp.client.streamable_http import streamablehttp_client
from strands import Agent
from strands.models import BedrockModel
from strands.tools.mcp import MCPClient

SYSTEM_PROMPT = """You operate TrustGate tools that run approved WebAssembly workloads inside an
attested enclave and return a signed receipt. Do all computation with those tools; never compute
results yourself. csv-stats takes the value column and then the group column as args.
When you verify a receipt, pass its receipt_id (never re-type the bundle) and report exactly which
checks passed, what kind of attestation was used, and whether the measurement matched. Never claim
more than the tools show: a receipt proves what code ran on what input in which environment, not
that the result is correct."""


def task(csv_text: str, pcr: str) -> str:
    pin = (f" and expected_measurement set to {pcr}" if pcr else
           " (no measurement is pinned, so say the measurement check was skipped)")
    return f"""Analyse these supplier payments in the enclave.

1. Call get_attestation and tell me the mode and measurement.
2. Run the csv-stats workload on this CSV with args ["amount","supplier"]:
{csv_text}
3. Report the total, the per-supplier sums and any anomalous payments.
4. Call verify_receipt with the receipt_id from step 2{pin}. Say which checks passed and what
   kind of attestation it was.
5. In two sentences: what does this receipt prove, and what does it NOT prove?"""


def text_of(result) -> str:
    """The text payload of an MCP tool result."""
    return "".join(c.get("text", "") for c in result.get("content", []))


def check(client: MCPClient, csv_text: str, pcr: str) -> int:
    """Exercise the MCP path directly, with no model."""
    tools = client.list_tools_sync()
    names = sorted(t.tool_name for t in tools)
    print("tools:", ", ".join(names))
    need = {"get_attestation", "execute", "verify_receipt", "list_workloads"}
    if not need <= set(names):
        print("missing tools:", need - set(names))
        return 1

    att = json.loads(text_of(client.call_tool_sync("t1", "get_attestation", {})))
    print("mode:", att["mode"], "| measurement:", att["measurement"][:32] + "...")

    res = client.call_tool_sync("t2", "execute", {"workload": "csv-stats", "input": csv_text, "args": ["amount", "supplier"]})
    out = json.loads(text_of(res))
    print("execute:", out["status"], "| receipt_id:", out["receipt_id"])
    print("output:", out["output"].strip()[:160])

    args = {"receipt_id": out["receipt_id"]}
    if pcr:
        args["expected_measurement"] = pcr
    ver = json.loads(text_of(client.call_tool_sync("t3", "verify_receipt", args)))
    for c in ver["checks"]:
        print(f"  [{c['status']}] {c['name']}")
    print("verified:", ver["verified"])
    return 0 if ver["verified"] else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="TrustGate MCP endpoint, e.g. http://localhost:18080/mcp")
    ap.add_argument("--pcr", default="", help="enclave PCR0 (hex) to pin when verifying")
    ap.add_argument("--csv", default="testdata/transactions.csv", help="CSV to analyse")
    ap.add_argument("--token", default=os.getenv("TRUSTGATE_TOKEN", ""), help="bearer token, if the server needs one")
    ap.add_argument("--check", action="store_true", help="test the MCP connection only (no model, no AWS credentials)")
    a = ap.parse_args()

    csv_text = Path(a.csv).read_text()
    headers = {"Authorization": f"Bearer {a.token}"} if a.token else None
    client = MCPClient(lambda: streamablehttp_client(a.url, headers=headers))

    with client:
        if a.check:
            return check(client, csv_text, a.pcr)

        model_id = os.getenv("BEDROCK_MODEL_ID")
        if not model_id:
            sys.exit("Set BEDROCK_MODEL_ID to the model or inference-profile ID shown in the Bedrock console "
                     "(it must be enabled for your account in this region). Use --check to test without a model.")
        model = BedrockModel(model_id=model_id, region_name=os.getenv("AWS_REGION", "ap-south-1"), temperature=0)
        agent = Agent(model=model, tools=client.list_tools_sync(), system_prompt=SYSTEM_PROMPT)
        agent(task(csv_text, a.pcr))
    return 0


if __name__ == "__main__":
    sys.exit(main())
