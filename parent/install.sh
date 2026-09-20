#!/usr/bin/env bash
# Installs the production setup on the enclave parent (Amazon Linux 2023): the
# enclave and forwarder as systemd services that start on boot, nginx in front,
# and a watchdog. Idempotent: run it again after changing the EIF or the files.
#
#   sudo parent/install.sh /home/ec2-user/demo.eif trustgate.example.com            # public endpoint
#   sudo parent/install.sh /home/ec2-user/demo.eif trustgate.example.com --with-kms # also enable the KMS proxy and credentials pusher
#
# Run from the repo root. bin/vsock-forwarder and bin/trustgate-parent must exist
# (they are built on the laptop and shipped in the tarball).
set -euo pipefail

EIF=${1:?usage: install.sh <path-to-enclave.eif> <public-hostname> [--with-kms]}
HOST=${2:?usage: install.sh <path-to-enclave.eif> <public-hostname> [--with-kms]}
WITH_KMS=${3:-}
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
cd "$(dirname "$0")/.."
[ -f "$EIF" ] || { echo "no such EIF: $EIF"; exit 1; }
for f in bin/vsock-forwarder bin/trustgate-parent; do
  [ -x "$f" ] || { echo "missing $f (build it on the laptop and ship bin/ in the tarball)"; exit 1; }
done

echo "== packages"
# Amazon Linux 2023 ships curl-minimal, which already provides /usr/bin/curl:
# asking dnf for a package named "curl" conflicts with it, so only install what is missing.
dnf install -y nginx jq >/dev/null
command -v curl >/dev/null || { echo "curl is missing; install curl-minimal"; exit 1; }

echo "== files"
install -d -m 755 /opt/trustgate
install -d -m 700 /etc/trustgate
install -m 755 bin/vsock-forwarder bin/trustgate-parent parent/watchdog.sh parent/update-cloudflare-ips.sh parent/origin-cert.sh /opt/trustgate/
ln -sfn "$(readlink -f "$EIF")" /opt/trustgate/enclave.eif

# CloudFront sends this secret as X-Origin-Verify; nginx refuses requests without it.
if [ ! -s /etc/trustgate/origin-secret ]; then
  ( umask 077; openssl rand -hex 32 > /etc/trustgate/origin-secret )
  echo "   created /etc/trustgate/origin-secret"
fi
SECRET=$(cat /etc/trustgate/origin-secret)

# Cloudflare's edge addresses (nginx accepts only these) and the origin key/CSR.
/opt/trustgate/update-cloudflare-ips.sh
# Show the CSR whenever there is no real certificate yet (none, or still the temporary self-signed one).
NEW_CSR=1
if [ -s /etc/trustgate/origin.crt ] && \
   [ "$(openssl x509 -in /etc/trustgate/origin.crt -noout -subject_hash)" != "$(openssl x509 -in /etc/trustgate/origin.crt -noout -issuer_hash)" ]; then
  NEW_CSR=0
fi
/opt/trustgate/origin-cert.sh csr "$HOST" > /etc/trustgate/origin.csr.pem

sed "s/__ORIGIN_SECRET__/$SECRET/" parent/nginx-trustgate.conf > /etc/nginx/conf.d/trustgate.conf
chmod 640 /etc/nginx/conf.d/trustgate.conf
nginx -t

install -m 644 parent/systemd/*.service parent/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload

echo "== stop anything that was started by hand, so the services own the enclave and the ports"
nitro-cli terminate-enclave --all >/dev/null 2>&1 || true
pkill -x vsock-forwarder 2>/dev/null || true
pkill -x vsock-proxy 2>/dev/null || true
pkill -f "trustgate-parent creds" 2>/dev/null || true

echo "== enable and start"
systemctl enable --now nitro-enclaves-allocator.service docker.service
systemctl enable --now trustgate-enclave.service trustgate-forwarder.service nginx.service trustgate-watchdog.timer trustgate-cloudflare-ips.timer
systemctl restart trustgate-enclave.service trustgate-forwarder.service nginx.service

if [ "$WITH_KMS" = "--with-kms" ]; then
  systemctl enable --now trustgate-kms-proxy.service trustgate-creds.service
  echo "   confidential jobs ENABLED (KMS proxy and credentials pusher running)"
else
  systemctl disable --now trustgate-kms-proxy.service trustgate-creds.service >/dev/null 2>&1 || true
  echo "   confidential jobs disabled (no credentials in the enclave): right for the public endpoint"
fi

echo "== check (the enclave needs a few seconds to boot)"
for i in $(seq 20); do curl -sf -m 3 http://127.0.0.1:8444/healthz >/dev/null && break; sleep 2; done
echo "enclave:   $(nitro-cli describe-enclaves | jq -r '.[0] | "\(.EnclaveName) \(.State) flags=\(.Flags)"')"
echo "server:    $(curl -s -m 3 http://127.0.0.1:8444/.well-known/trustgate | jq -c '{mode, measurement}')"
echo "health:    $(curl -s -m 3 http://127.0.0.1:8444/healthz)"
echo "nginx:     $(curl -sk -o /dev/null -w 'direct request (not from Cloudflare) -> HTTP %{http_code} (expect 403)' https://127.0.0.1/healthz)"
echo
echo "origin secret (for the Cloudflare header rule):  sudo cat /etc/trustgate/origin-secret"
if [ "$NEW_CSR" = 1 ]; then
  echo
  echo "== Next: get a Cloudflare origin certificate. Paste this CSR into Cloudflare"
  echo "   (SSL/TLS, Origin Server, Create Certificate, 'Use my private key and CSR'):"
  echo
  cat /etc/trustgate/origin.csr.pem
  echo
  echo "   then install the certificate Cloudflare returns:  sudo /opt/trustgate/origin-cert.sh install   (paste it, then Ctrl-D)"
else
  echo "origin certificate already present: $(openssl x509 -in /etc/trustgate/origin.crt -noout -subject -enddate | tr '\n' ' ')"
fi
