import Reveal from "./components/Reveal";

const GITHUB = "https://github.com/rishi-xyz/trustgate";

const eyebrow = "font-mono text-[0.78rem] uppercase tracking-[0.06em]";
const wrap = "mx-auto max-w-[1120px] px-6";
const h2 = "text-[clamp(2rem,4vw,3rem)] max-w-[16em]";
const lede = "mt-[18px] max-w-[38em] text-[1.1rem] text-muted";
const btn =
  "inline-flex items-center gap-2 rounded-full border border-line bg-card px-5 py-[11px] text-[0.95rem] font-medium text-fg no-underline transition hover:-translate-y-px hover:shadow-soft";
const btnPrimary = `${btn} !border-fg !bg-fg !text-bg`;
const card = "rounded-2xl border border-line bg-card p-7";

const checks = [
  "Receipt signature matches contents",
  "Attestation matches hash in receipt",
  "Nitro attestation verified against AWS root CA",
  "Signing key bound by the attestation",
  "Enclave measurement matches pinned PCR0",
];

const steps = [
  ["01", "Submit", "An agent calls an MCP tool with an approved, publisher-signed workload and an input."],
  ["02", "Isolate", "The workload runs in wazero inside a Nitro Enclave. No capabilities unless granted, with CPU and memory limits."],
  ["03", "Attest", "The receipt-signing key is bound to a Nitro attestation document. Receipts are hash-chained and Ed25519-signed."],
  ["04", "Verify", "Anyone checks the receipt against the AWS root CA and a pinned measurement, from somewhere else. Deterministic jobs can be replayed."],
];

const pillars = [
  ["01", "Tamper-evident", "Edited receipts, changed inputs and wrong pinned measurements all fail verification. These are covered by attack tests and were run on real hardware."],
  ["02", "Measurement-gated keys", "AWS KMS releases a secret only to the enclave with the exact measured image. The parent instance's own credentials, and a modified image, are denied."],
  ["03", "Independently verifiable", "A separate Lambda verifier checks signature, attestation and key binding, so the server that ran your job is not the one grading it."],
];

const tools: [string, string][] = [
  ["execute", "Run an approved workload, with text or raw-bytes input. Returns output plus a signed receipt. Add sealed_input for a confidential job."],
  ["execute_async · job_status · job_result · cancel_job", "Long-running jobs: get a job id at once, poll, fetch the result, or cancel."],
  ["replay", "Re-run the workload in a receipt against the original input and compare output hashes."],
  ["verify_receipt", "Check signature, attestation, key binding and an optional pinned measurement, by short receipt id or full bundle."],
  ["list_workloads · get_attestation", "Discover approved workloads and the server's attestation evidence."],
];

const relyOn = [
  "The workload hash and input the receipt commits to",
  "The enclave image measured by the attestation document",
  "The receipt not having been edited after signing",
  "Confidential inputs staying encrypted outside the enclave",
];

const gaps = [
  "Whether a rebuilt enclave image gets the same PCR0 is not yet confirmed for every build; until it is, a rebuild means updating the KMS key policy",
  "Transport to the MCP endpoint is plain HTTP",
  "The parent still sees metadata and can delay or drop jobs",
  "dev mode has no hardware isolation and is rejected by the verifier by default",
];

export default function Home() {
  return (
    <>
      <nav className="sticky top-0 z-10 bg-bg/80 backdrop-blur-md">
        <div className={`${wrap} flex h-16 items-center justify-between`}>
          <a href="#top" aria-label="TrustGate home" className="flex items-center gap-2.5 font-serif text-xl no-underline">
            <svg viewBox="0 0 32 32" fill="none" aria-hidden="true" className="h-[26px] w-[26px]">
              <rect x="3" y="3" width="26" height="26" rx="8" stroke="currentColor" strokeWidth="2" />
              <path d="M10 16.5l4 4 8-9" stroke="var(--accent)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            TrustGate
          </a>
          <div className="flex items-center gap-7 text-[0.92rem] text-muted">
            {[
              ["#how", "How it works"],
              ["#confidential", "Confidential jobs"],
              ["#tools", "MCP tools"],
              ["#honest", "Guarantees"],
            ].map(([href, label]) => (
              <a key={href} href={href} className="hidden no-underline hover:text-fg sm:inline">
                {label}
              </a>
            ))}
            <a className={btnPrimary} href="/verify/">Verify a receipt</a>
          </div>
        </div>
      </nav>

      <header id="top" className="relative overflow-hidden pb-[72px] pt-14 md:pt-24">
        <div
          aria-hidden="true"
          className="absolute -inset-x-[10%] -top-[20%] -z-10 h-[120%] blur-[20px]"
          style={{
            background:
              "radial-gradient(600px 380px at 78% 18%, color-mix(in srgb, var(--accent) 28%, transparent), transparent 70%), radial-gradient(520px 340px at 92% 55%, color-mix(in srgb, var(--accent3) 30%, transparent), transparent 70%), radial-gradient(560px 360px at 60% 5%, color-mix(in srgb, var(--accent2) 22%, transparent), transparent 70%)",
          }}
        />
        <div className={`${wrap} grid items-center gap-14 md:grid-cols-[1.05fr_.95fr]`}>
          <div>
            <span className={`${eyebrow} inline-flex items-center gap-2 rounded-full border border-line bg-card px-3 py-1.5 !text-[0.8rem] text-muted`}>
              <span className="h-[7px] w-[7px] rounded-full bg-ok shadow-[0_0_0_4px_color-mix(in_srgb,var(--ok)_20%,transparent)]" />
              Verified on real AWS Nitro hardware
            </span>
            <h1 className="my-[22px] text-[clamp(2.6rem,6vw,4.6rem)]">
              Don&apos;t trust the agent&apos;s output. <em className="italic text-accent">Check the receipt.</em>
            </h1>
            <p className="mb-8 max-w-[34em] text-[1.15rem] text-muted">
              TrustGate runs approved WebAssembly workloads for AI agents inside an AWS Nitro Enclave, then hands back a
              signed receipt that proves which code ran, on which input, in which measured environment.
            </p>
            <div className="flex flex-wrap gap-3">
              <a className={btnPrimary} href="/verify/">Verify a receipt &rarr;</a>
              <a className={btn} href={GITHUB}>View on GitHub</a>
            </div>
            <p className="mt-[22px] text-[0.85rem] text-muted">Proof of execution and environment, not proof of correctness.</p>
          </div>

          <div aria-label="Example verification result" className="overflow-hidden rounded-[18px] border border-line bg-card shadow-soft">
            <div className="flex items-center justify-between border-b border-line px-[18px] py-3.5 font-mono text-[0.78rem] font-medium text-muted">
              <span>receipt · csv-stats</span>
              <span>mode: nitro</span>
            </div>
            <div className="p-[18px] font-mono text-[0.8rem] leading-[1.7]">
              {[
                ["workload", "csv-stats"],
                ["signer", "ed25519:798c4fe4…"],
                ["PCR0", "ac40e634…01da07"],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between gap-4">
                  <span className="text-muted">{k}</span>
                  <span className="break-all text-right">{v}</span>
                </div>
              ))}
            </div>
            <ul className="m-0 list-none px-[18px] pb-[18px] pt-1.5">
              {checks.map((c, i) => (
                <li key={c} className="rise flex items-center gap-2.5 border-t border-line py-[9px] text-[0.88rem]" style={{ animationDelay: `${0.5 + i * 0.5}s` }}>
                  <span className="grid h-5 w-5 flex-none place-items-center rounded-full bg-ok/15 text-[0.7rem] font-bold text-ok">&#10003;</span>
                  {c}
                </li>
              ))}
            </ul>
            <div className="rise border-t border-line bg-ok/10 px-[18px] py-3.5 font-mono text-[0.78rem] font-medium text-ok" style={{ animationDelay: "3s" }}>
              EXECUTION VERIFIED
            </div>
          </div>
        </div>
      </header>

      <section id="how" className="py-[88px]">
        <Reveal className={wrap}>
          <div className={`${eyebrow} mb-3.5 text-accent`}>How it works</div>
          <h2 className={h2}>From agent request to independent proof.</h2>
          <p className={lede}>
            An MCP agent submits a job. It runs under deny-by-default capabilities and resource limits. What comes back is
            the result plus evidence, not a promise.
          </p>
          <div className="mt-[52px] grid overflow-hidden rounded-2xl border border-line bg-card md:grid-cols-4">
            {steps.map(([n, t, d]) => (
              <div key={n} className="border-b border-line p-[26px] last:border-b-0 md:border-b-0 md:border-r md:last:border-r-0">
                <span className="font-mono text-[0.72rem] font-medium text-accent2">{n}</span>
                <b className="mb-1.5 mt-2.5 block font-serif text-[1.15rem] font-medium">{t}</b>
                <p className="m-0 text-[0.9rem] text-muted">{d}</p>
              </div>
            ))}
          </div>
        </Reveal>
      </section>

      <section className="border-y border-line bg-bg2 py-[88px]">
        <Reveal className={wrap}>
          <div className={`${eyebrow} mb-3.5 text-accent`}>Why it holds up</div>
          <h2 className={h2}>Built to survive a hostile host.</h2>
          <div className="mt-12 grid gap-5 md:grid-cols-3">
            {pillars.map(([n, t, d]) => (
              <div key={n} className={card}>
                <div className="font-mono text-[0.8rem] font-medium text-accent">{n}</div>
                <h3 className="mb-2.5 mt-3.5 text-[1.4rem]">{t}</h3>
                <p className="m-0 text-[0.97rem] text-muted">{d}</p>
              </div>
            ))}
          </div>
        </Reveal>
      </section>

      <section id="confidential" className="relative overflow-hidden bg-ink py-[88px] text-ink-fg">
        <div aria-hidden="true" className="absolute -right-[10%] -top-[30%] h-[600px] w-[600px]" style={{ background: "radial-gradient(closest-side, rgba(99,102,241,.35), transparent)" }} />
        <Reveal className={`${wrap} relative grid items-center gap-14 md:grid-cols-2`}>
          <div>
            <div className={`${eyebrow} mb-3.5 text-accent3`}>Confidential jobs</div>
            <h2 className={h2}>The host handles ciphertext. Only the enclave sees your data.</h2>
            <p className={`${lede} !text-ink-muted`}>
              The data owner seals an input to one exact job. The attested enclave unwraps it, runs it, and seals the
              result back to the owner&apos;s key.
            </p>
            <ul className="m-0 mt-7 list-none p-0">
              {[
                ["Bound to one job.", "A hostile parent can't re-target the ciphertext at another workload, change arguments, or redirect the result."],
                ["Salted receipts.", "Hashes use secrets only the owner holds, so small or guessable data can't be brute-forced from a receipt."],
                ["Observed on the wire.", "A packet capture on the parent held none of the sealed job's data or results, while the same job unsealed did."],
              ].map(([b, t]) => (
                <li key={b} className="border-t border-ink-line py-3.5 text-[0.97rem] text-ink-muted">
                  <b className="font-medium text-ink-fg">{b}</b> {t}
                </li>
              ))}
            </ul>
          </div>
          <pre aria-label="Sealed job flow" className="m-0 overflow-auto rounded-[14px] border border-ink-line bg-[#0a0c16] p-[22px] font-mono text-[0.8rem] leading-[1.7] text-[#c9cee6]">
            <span className="text-[#6c728f]"># data owner</span>{"\n"}
            $ trustgate seal --workload csv-stats ...{"\n"}
            {"  "}<span className="text-[#4cc38a]">&#10003;</span> input encrypted, data key wrapped by KMS{"\n\n"}
            <span className="text-[#6c728f]"># parent instance sees</span>{"\n"}
            {"  "}ciphertext, sizes, timing{"\n\n"}
            <span className="text-[#6c728f]"># attacker re-targets the job</span>{"\n"}
            {"  "}<span className="text-[#ff7b72]">&#10007; refused: authentication failed</span>{"\n\n"}
            <span className="text-[#6c728f]"># enclave (attested KMS call)</span>{"\n"}
            {"  "}<span className="text-[#4cc38a]">&#10003;</span> unwrap &rarr; run &rarr; seal result to owner key
          </pre>
        </Reveal>
      </section>

      <section id="tools" className="py-[88px]">
        <Reveal className={wrap}>
          <div className={`${eyebrow} mb-3.5 text-accent`}>Agent interface</div>
          <h2 className={h2}>Plain MCP tools your agent already understands.</h2>
          <p className={lede}>
            Streamable HTTP at <code className="font-mono">/mcp</code>. Works with any MCP client; a Strands agent on
            Bedrock is included as an example.
          </p>
          <div className="mt-10 overflow-hidden rounded-2xl border border-line bg-card">
            {tools.map(([name, desc], i) => (
              <div key={name} className={`grid gap-1 px-[22px] py-4 text-[0.94rem] md:grid-cols-[minmax(0,320px)_1fr] md:gap-6 ${i ? "border-t border-line" : ""}`}>
                <div className="font-mono text-[0.85rem] font-medium text-accent">{name}</div>
                <div className="text-muted">{desc}</div>
              </div>
            ))}
          </div>
        </Reveal>
      </section>

      <section id="honest" className="border-y border-line bg-bg2 py-[88px]">
        <Reveal className={wrap}>
          <div className={`${eyebrow} mb-3.5 text-accent`}>Guarantees</div>
          <h2 className={h2}>What it proves, and what it doesn&apos;t.</h2>
          <div className="mt-11 rounded-2xl border border-line bg-card px-[30px] py-[26px] font-serif text-[1.35rem] leading-[1.4]">
            TrustGate proves <em className="text-accent">what code ran, on which input, in which environment.</em> It does
            not prove the result is correct.
          </div>
          <div className="mt-5 grid gap-5 md:grid-cols-2">
            {[
              ["You can rely on", relyOn],
              ["Known gaps", gaps],
            ].map(([title, items]) => (
              <div key={title as string} className={card}>
                <h3 className="text-[1.2rem]">{title as string}</h3>
                <ul className="mb-0 mt-3 list-disc pl-[1.1em] text-[0.95rem] text-muted">
                  {(items as string[]).map((x) => (
                    <li key={x} className="my-1.5">{x}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </Reveal>
      </section>

      <section className="relative overflow-hidden py-[104px] text-center">
        <div
          aria-hidden="true"
          className="absolute inset-0 -z-10"
          style={{
            background:
              "radial-gradient(500px 260px at 50% 100%, color-mix(in srgb, var(--accent) 25%, transparent), transparent 70%), radial-gradient(400px 240px at 20% 100%, color-mix(in srgb, var(--accent3) 25%, transparent), transparent 70%)",
          }}
        />
        <Reveal className={wrap}>
          <h2 className={`${h2} mx-auto`}>Paste a receipt. See for yourself.</h2>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <a className={btnPrimary} href="/verify/">Open the verifier &rarr;</a>
            <a className={btn} href={GITHUB}>Read the source</a>
          </div>
        </Reveal>
      </section>

      <footer className="border-t border-line py-7 text-[0.85rem] text-muted">
        <div className={`${wrap} flex flex-wrap justify-between gap-3`}>
          <span>TrustGate · attested compute for AI agents</span>
          <span>Built on AWS Nitro Enclaves, KMS and Lambda</span>
        </div>
      </footer>
    </>
  );
}
