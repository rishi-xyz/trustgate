# Running TrustGate as a public endpoint

This is the runbook for the public, open (no login) deployment. Everything here was tested locally or on the instance as noted in `docs/evidence.md`; steps that need your AWS account are marked **[you]**.

## Architecture

```
agent -> https://<DOMAIN>/mcp
           |  CloudFront: ACM certificate, WAF (per-IP rate limit, IP reputation), adds X-Origin-Verify
           v
        Elastic IP :8443   security group: CloudFront origin-facing prefix list only
           |  nginx on the parent: checks X-Origin-Verify, 4 MiB body cap, 10 req/s per viewer, timeouts
           v
        127.0.0.1:8444     vsock-forwarder (systemd)
           |  vsock
           v
        Nitro Enclave      hardened server: stateless MCP, 2 workers, queue timeout, body cap, health counters
```

## What protects what

| Layer | Stops | Does not stop |
|---|---|---|
| WAF (edge) | one IP flooding the endpoint; addresses on the Amazon IP reputation list | many distinct IPs at once |
| Security group + secret header | anyone reaching the instance except through your CloudFront distribution | someone who learns the secret |
| nginx | oversized bodies, bursts per viewer, slow clients | |
| Server (enclave) | too many concurrent runs (2 workers, then "server busy"), oversized bodies, slow requests | |
| Workload sandbox | filesystem, network, clock, randomness, memory and time overruns | |
| Application-layer sealing | the edge, nginx and the operator reading confidential inputs and results | metadata: timing, sizes, which workload |

CloudFront, nginx and the operator can read **unsealed** traffic. The public endpoint is for sample data only, and says so in the judge guide.

## Deploy

**1. Build the new enclave image on the parent [you].** The server changed, so this is a new measurement.

```bash
# laptop: make publish && CGO_ENABLED=0 go build -buildvcs=false -trimpath -o bin/ ./cmd/... then tar and scp as before
make eif-check                       # must print REPRODUCIBLE
cp build/check2.eif ~/prod.eif
cat build/pcr2                     # the PCR0 to publish (eif-check writes it here)
```

Update the KMS key policy's `kms:RecipientAttestation:ImageSha384` to this PCR0 (only matters for confidential jobs; keep it consistent).

**2. Install the services [you].**

```bash
sudo parent/install.sh /home/ec2-user/prod.eif
```

Expected: enclave `RUNNING flags=NONE`, server `mode: nitro`, `health` JSON, and `no origin header -> HTTP 403`. The enclave, forwarder, nginx and the watchdog now start on boot. Confidential jobs are **off** (no credentials in the enclave); add `--with-kms` only for a private window.

**3. Stable address [you].** EC2, Elastic IPs, Allocate, Associate with the instance. Note the **public DNS name** of the Elastic IP (`ec2-x-x-x-x.ap-south-1.compute.amazonaws.com`).

**4. Certificate [you].** ACM in **us-east-1**, Request a public certificate for `<DOMAIN>`, DNS validation, add the CNAME it shows at your DNS provider, wait until it says Issued. Copy its ARN.

**5. Edge stack [you].** CloudFormation in **us-east-1**, Create stack, Upload `infra/edge-us-east-1.yaml`. Parameters: `DomainName`, `CertificateArn`, `OriginDnsName` (step 3), `OriginSecret` (`sudo cat /etc/trustgate/origin-secret` on the instance). Note the `CloudFrontDomainName` output.

**6. DNS [you].** At your DNS provider add `CNAME <DOMAIN> -> <CloudFrontDomainName>`.

**7. Lock the origin [you].** Security group of the instance: remove the old 8443 rule for your IP; add an inbound rule for 8443 whose source is the managed prefix list `com.amazonaws.global.cloudfront.origin-facing`. If AWS refuses because of the rules-per-group quota, request an increase (this prefix list counts as many rules). Close SSH once you rely on Session Manager, or keep it limited to your IP.

**8. Hardening [you].** Require IMDSv2 on the instance; encrypt the EBS volume for future instances; add a CloudWatch alarm on `StatusCheckFailed_System` with the **Recover** action.

**9. Test.**

```bash
curl -s https://<DOMAIN>/.well-known/trustgate | jq '{mode, measurement}'       # nitro + the published PCR0
curl -s -o /dev/null -w '%{http_code}\n' http://<ELASTIC_IP>:8443/healthz       # from the internet: must NOT succeed
agents/.venv/bin/python agents/strands_demo.py --url https://<DOMAIN>/mcp --pcr <PCR0> --check
TRUSTGATE_URL=https://<DOMAIN> PCR=<PCR0> PAUSE=0 scripts/demo-enclave.sh
```

## Operate

| Task | How |
|---|---|
| Health | `curl -s https://<DOMAIN>/healthz` shows workers, in-flight, queued, executed, rejected_busy (counters only) |
| Logs | on the parent: `journalctl -u trustgate-enclave -u trustgate-forwarder -u trustgate-watchdog`, `/var/log/nginx/access.log`. The enclave itself has no console in production mode |
| Restart | `sudo systemctl restart trustgate-enclave trustgate-forwarder` (also what the watchdog does after 3 failed checks) |
| Roll a new build | build it, `make eif-check`, update the KMS policy PCR0, `ln -sfn ~/new.eif /opt/trustgate/enclave.eif`, restart the enclave; **publish the new PCR0** |
| Roll back | repoint `/opt/trustgate/enclave.eif` to the previous image and restart |
| Rotate the origin secret | new value in `/etc/trustgate/origin-secret`, re-run `parent/install.sh`, update the stack's `OriginSecret` |
| Emergency stop | CloudFront, disable the distribution (fastest), or stop the instance |
| Private confidential window | `sudo parent/install.sh /home/ec2-user/prod.eif --with-kms`, then back without the flag afterwards |
| Change the rate limit | update the stack parameter `RateLimitPer5Min` |

## Limits, stated plainly

- **One instance.** A crash or recovery is a short outage (the watchdog restarts the enclave in about two minutes; instance recovery takes longer). There is no failover.
- **Open access.** Anyone can use the two vCPUs. The layers above reduce abuse, they do not remove it; a distributed flood would still get through the per-IP limits and reach "server busy".
- **Unsealed traffic is visible** to CloudFront, nginx and the operator. Attested TLS inside the enclave is the next step and is not done.
- **No persistent logs or receipt archive.** Receipt ids exist only until the enclave restarts; the full receipt bundle a caller receives never expires.
- **Attestation does not make a workload correct.**
- Build reproducibility was confirmed on one machine with pinned inputs; a different Nitro CLI version could change the measurement.

## Rough cost (check current prices)

WAF: about $5 per web ACL plus $1 per rule per month and $0.60 per million requests. CloudFront: within the free tier for this traffic. Instance, Elastic IP and EBS at their hourly rates. A judging window costs a few dollars; the account budget alarm remains in place.
