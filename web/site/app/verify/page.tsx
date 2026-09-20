"use client";

import { useState } from "react";

type Check = { name: string; status: "pass" | "fail" | "skip"; detail?: string };
type Result = { verified: boolean; checks: Check[]; note?: string };

const MARK = { pass: "✓", fail: "✗", skip: "–" } as const;
const TONE = { pass: "text-ok", fail: "text-bad", skip: "text-accent3" } as const;

const field =
  "w-full rounded-lg border border-line bg-card p-2.5 font-mono text-[0.8rem] leading-[1.4] text-fg outline-none focus:border-accent";
const label = "mb-1.5 mt-4 block font-semibold";
const hint = "mt-1 text-[0.85rem] text-muted";

export default function VerifyPage() {
  const [receipt, setReceipt] = useState("");
  const [pin, setPin] = useState("");
  const [api, setApi] = useState(process.env.NEXT_PUBLIC_VERIFIER_URL ?? "http://127.0.0.1:3000");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Result | null>(null);

  async function run() {
    setError("");
    setResult(null);
    let bundle: unknown;
    try {
      bundle = JSON.parse(receipt);
    } catch {
      setError("The receipt is not valid JSON.");
      return;
    }

    const base = api.trim().replace(/\/+$/, "");
    setBusy(true);
    try {
      const res = await fetch(base + "/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ receipt_bundle: bundle, expected_measurement: pin.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || `Verifier returned ${res.status}`);
        return;
      }
      setResult(data);
    } catch (e) {
      setError(`Could not reach the verifier at ${base}. Is it running? (${(e as Error).message})`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <nav className="border-b border-line">
        <div className="mx-auto flex h-16 max-w-[760px] items-center justify-between px-4">
          <a href="/" className="flex items-center gap-2.5 font-serif text-xl no-underline">
            <svg viewBox="0 0 32 32" fill="none" aria-hidden="true" className="h-[26px] w-[26px]">
              <rect x="3" y="3" width="26" height="26" rx="8" stroke="currentColor" strokeWidth="2" />
              <path d="M10 16.5l4 4 8-9" stroke="var(--accent)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            TrustGate
          </a>
          <a href="/" className="text-[0.92rem] text-muted no-underline hover:text-fg">&larr; Back to home</a>
        </div>
      </nav>

      <main className="mx-auto max-w-[760px] px-4 pb-16 pt-10">
        <h1 className="mb-2 text-[2.2rem]">Receipt verifier</h1>
        <p className="mb-5 text-muted">
          Paste a receipt and the enclave measurement you expect. This page asks an independent verifier, not the server
          that ran the job, to check the signature, the AWS Nitro attestation and the key binding.
        </p>

        <label htmlFor="receipt" className={label}>Receipt bundle (JSON)</label>
        <textarea
          id="receipt"
          value={receipt}
          onChange={(e) => setReceipt(e.target.value)}
          spellCheck={false}
          placeholder='{"attestation": "...", "receipt": {...}, "sig": "ed25519:..."}'
          className={`${field} min-h-[180px] resize-y`}
        />
        <div className={hint}>
          The file saved by <code className="font-mono">trustgate exec</code>, or the <code className="font-mono">receipt_bundle</code> from an MCP result.
        </div>

        <label htmlFor="pin" className={label}>Expected enclave measurement (PCR0, hex)</label>
        <input
          id="pin"
          value={pin}
          onChange={(e) => setPin(e.target.value)}
          spellCheck={false}
          placeholder="96 hex characters. Leave empty to skip the measurement check."
          className={field}
        />
        <div className={hint}>Without a pinned measurement the check is skipped, and you have not confirmed which enclave image ran.</div>

        <label htmlFor="api" className={label}>Verifier API address</label>
        <input id="api" value={api} onChange={(e) => setApi(e.target.value)} className={field} />

        <button
          onClick={run}
          disabled={busy}
          className="mt-4 cursor-pointer rounded-full bg-fg px-6 py-[11px] font-medium text-bg transition hover:-translate-y-px disabled:cursor-default disabled:opacity-60"
        >
          {busy ? "Verifying…" : "Verify"}
        </button>

        <div aria-live="polite">
          {result && (
            <section className="mt-6 rounded-xl border border-line bg-card p-4">
              <p className={`mb-2.5 text-[1.1rem] font-bold ${result.verified ? "text-ok" : "text-bad"}`}>
                {result.verified ? "Verified: what ran and where is confirmed" : "Verification FAILED"}
              </p>
              <ul className="m-0 list-none p-0">
                {result.checks.map((c) => (
                  <li key={c.name} className="grid grid-cols-[1.4em_1fr] gap-x-2 gap-y-1 border-t border-line py-1.5 first:border-t-0">
                    <span className={`font-bold ${TONE[c.status]}`}>{MARK[c.status] ?? "?"}</span>
                    <span className="font-semibold">{c.name}</span>
                    {c.detail && <span className="col-start-2 break-words text-[0.88rem] text-muted">{c.detail}</span>}
                  </li>
                ))}
              </ul>
              {result.note && <p className="mt-3 text-[0.88rem] text-muted">{result.note}</p>}
            </section>
          )}
        </div>
        {error && <p className="mt-3 text-bad">{error}</p>}

        <details className="mt-5 text-[0.88rem] text-muted">
          <summary className="cursor-pointer">What this does and does not show</summary>
          <p>
            A pass means: the receipt is signed by a key that a genuine AWS Nitro attestation document vouches for, and
            (if you pinned it) that document names the enclave image you expected. It does not mean the workload&apos;s
            answer is correct, and AWS Nitro remains the root of trust.
          </p>
        </details>
      </main>
    </>
  );
}
