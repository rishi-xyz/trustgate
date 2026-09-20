# Running TrustGate as a public endpoint

This is the runbook for the public, open (no login) deployment. Everything here was tested locally or on the instance as noted in `docs/evidence.md`; steps that need your AWS account are marked **[you]**.

## Architecture

```
agent -> https://<DOMAIN>/mcp
           |  Cloudflare (proxied DNS): TLS for visitors, rate limit, adds the secret header X-Origin-Verify
           v
        Elastic IP :443     HTTPS to the origin (Cloudflare "Full (strict)", Cloudflare Origin CA certificate)
           |  nginx on the parent: accepts only Cloudflare's published addresses AND the secret header,
           |  4 MiB body cap, 10 req/s per real visitor (CF-Connecting-IP), timeouts
           v
        127.0.0.1:8444      vsock-forwarder (systemd)
           |  vsock
           v
        Nitro Enclave       hardened server: stateless MCP, 2 workers, queue timeout, body cap, health counters
```

An earlier design used CloudFront and AWS WAF (`infra/edge-us-east-1.yaml`, kept in the repo). AWS refused to create the distribution until the account is verified ("Your account must be verified before you can add new CloudFront resources"), so the deployed edge is Cloudflare. The template still lints clean and is a drop-in alternative once the account is verified.

## What protects what

| Layer | Stops | Does not stop |
|---|---|---|
| Cloudflare (edge) | TLS termination for visitors; one IP flooding the endpoint (free plan: one rate rule, 10 s window, per IP); its own baseline DDoS protection | a distributed flood that stays under the per-IP limit |
| nginx: Cloudflare-only + secret header | anyone reaching the origin directly, or through someone else's Cloudflare account | someone who learns the secret |
| nginx: limits | oversized bodies, bursts per visitor, slow clients | |
| Server (enclave) | too many concurrent runs (2 workers, then "server busy"), oversized bodies, slow requests | |
| Workload sandbox | filesystem, network, clock, randomness, memory and time overruns | |
| Application-layer sealing | Cloudflare, nginx and the operator reading confidential inputs and results | metadata: timing, sizes, which workload |

Cloudflare, nginx and the operator can read **unsealed** traffic. The public endpoint is for sample data only, and says so in the judge guide.

## Deploy

**1. Build the enclave image on the parent [you].** The server changed, so this is a new measurement.

```bash
# laptop: make publish && CGO_ENABLED=0 go build -buildvcs=false -trimpath -o bin/ ./cmd/... then tar and scp as before
make eif-check                       # must print REPRODUCIBLE
cp build/check2.eif ~/prod.eif
cat build/pcr2                       # the PCR0 to publish (eif-check writes it here)
```

Update the KMS key policy's `kms:RecipientAttestation:ImageSha384` to this PCR0 (only matters for confidential jobs; keep it consistent).

**2. Install the services [you].**

```bash
sudo parent/install.sh /home/ec2-user/prod.eif <DOMAIN>
```

It installs nginx, systemd units, the Cloudflare address list (refreshed weekly), the origin secret, and a private key with a certificate signing request (CSR), which it prints. Expected: enclave `RUNNING flags=NONE`, server `mode: nitro`, `health` JSON, and `direct request (not from Cloudflare) -> HTTP 403`. Confidential jobs are **off** (no credentials in the enclave); add `--with-kms` only for a private window.

**3. Stable address [you].** EC2, Elastic IPs, Allocate, Associate with the instance.

**4. Origin certificate [you].** Cloudflare, SSL/TLS, Origin Server, Create Certificate, **Use my private key and CSR**, paste the CSR from step 2, hostname `<DOMAIN>`, create. Copy the certificate and install it on the parent: `sudo /opt/trustgate/origin-cert.sh install`, paste, Ctrl-D. (The private key never leaves the instance; the helper refuses a self-signed certificate or one issued for a different key.)

**5. Cloudflare settings [you].**

- **DNS:** `A  <name>  ->  <ELASTIC_IP>`, **Proxied** (orange cloud).
- **SSL/TLS, Overview:** mode **Full (strict)**.
- **Rules, Transform Rules, Modify Request Header:** when hostname equals `<DOMAIN>`, **Set static** header `X-Origin-Verify` = the value of `/etc/trustgate/origin-secret`.
- **Security, Bots:** **Bot Fight Mode off**. It challenges non-browser clients, which is every MCP agent, and Cloudflare says it ignores WAF skip rules.
- **Rules, Configuration Rules:** for hostname `<DOMAIN>`, **Browser Integrity Check off** (it can block non-browser clients such as curl).
- **Security, WAF, Rate limiting rules:** hostname equals `<DOMAIN>`; counted per IP; about 50 requests per 10 seconds; action Block. (Free plan: one rule, 10-second window, IP only; nginx adds its own limit.)

**6. Open the port [you].** Security group of the instance: inbound `443` from `0.0.0.0/0` and `::/0`; remove the old `8443` rule. The origin refuses everything that is not Cloudflare plus the secret header at nginx, so the group can be open. (Optional hardening: restrict 443 to Cloudflare's ranges in the group as well.)

**7. Test.**

```bash
curl -s https://<DOMAIN>/.well-known/trustgate | jq '{mode, measurement}'   # nitro + the published PCR0
curl -sk -o /dev/null -w '%{http_code}\n' https://<ELASTIC_IP>/healthz       # direct to the origin: must be 403
agents/.venv/bin/python agents/strands_demo.py --url https://<DOMAIN>/mcp --pcr <PCR0> --check
TRUSTGATE_URL=https://<DOMAIN> PCR=<PCR0> PAUSE=0 scripts/demo-enclave.sh
```

The local regression test for the nginx layer is `parent/test-nginx.sh` (Docker required). It checks the real Cloudflare ranges, a real-length secret, the certificate helper and the address updater.

## Operate

| Task | How |
|---|---|
| Health | `curl -s https://<DOMAIN>/healthz` shows workers, in-flight, queued, executed, rejected_busy (counters only) |
| Logs | on the parent: `journalctl -u trustgate-enclave -u trustgate-forwarder -u trustgate-watchdog`, `/var/log/nginx/access.log`. The enclave itself has no console in production mode |
| Restart | `sudo systemctl restart trustgate-enclave trustgate-forwarder` (also what the watchdog does after 3 failed checks) |
| Roll a new build | build it, `make eif-check`, update the KMS policy PCR0, `ln -sfn ~/new.eif /opt/trustgate/enclave.eif`, restart the enclave; **publish the new PCR0** |
| Roll back | repoint `/opt/trustgate/enclave.eif` to the previous image and restart |
| Rotate the origin secret | new value in `/etc/trustgate/origin-secret`, re-run `parent/install.sh`, update the Cloudflare header rule |
| Emergency stop | Cloudflare: switch the DNS record to DNS only or delete it (fastest), or stop the instance |
| Private confidential window | `sudo parent/install.sh /home/ec2-user/prod.eif --with-kms`, then back without the flag afterwards |
| Change the rate limit | Cloudflare WAF rate-limit rule; nginx `rate=` in `parent/nginx-trustgate.conf` |

## Limits, stated plainly

- **One instance.** A crash or recovery is a short outage (the watchdog restarts the enclave in about two minutes; instance recovery takes longer). There is no failover.
- **Open access.** Anyone can use the two vCPUs. The layers above reduce abuse, they do not remove it; a distributed flood would still get through the per-IP limits and reach "server busy".
- **Unsealed traffic is visible** to Cloudflare, nginx and the operator. Attested TLS inside the enclave is the next step and is not done.
- **No persistent logs or receipt archive.** Receipt ids exist only until the enclave restarts; the full receipt bundle a caller receives never expires.
- **Attestation does not make a workload correct.**
- Build reproducibility was confirmed on one machine with pinned inputs; a different Nitro CLI version could change the measurement.

## Rough cost (check current prices)

Cloudflare: free plan. Instance, Elastic IP and EBS at their hourly rates. A judging window costs a few dollars; the account budget alarm remains in place.
