#!/usr/bin/env bash
# Installs the production setup on the enclave parent (Amazon Linux 2023): the
# enclave and forwarder as systemd services that start on boot, nginx in front,
# and a watchdog. Idempotent: run it again after changing the EIF or the files.
#
#   sudo parent/install.sh /home/ec2-user/demo.eif            # public endpoint
#   sudo parent/install.sh /home/ec2-user/demo.eif --with-kms # also enable the KMS proxy and credentials pusher
#
# Run from the repo root. bin/vsock-forwarder and bin/trustgate-parent must exist
# (they are built on the laptop and shipped in the tarball).
set -euo pipefail

EIF=${1:?usage: install.sh <path-to-enclave.eif> [--with-kms]}
WITH_KMS=${2:-}
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
cd "$(dirname "$0")/.."
[ -f "$EIF" ] || { echo "no such EIF: $EIF"; exit 1; }
for f in bin/vsock-forwarder bin/trustgate-parent; do
  [ -x "$f" ] || { echo "missing $f (build it on the laptop and ship bin/ in the tarball)"; exit 1; }
done

echo "== packages"
dnf install -y nginx jq curl >/dev/null

echo "== files"
install -d -m 755 /opt/trustgate
install -d -m 700 /etc/trustgate
install -m 755 bin/vsock-forwarder bin/trustgate-parent parent/watchdog.sh /opt/trustgate/
ln -sfn "$(readlink -f "$EIF")" /opt/trustgate/enclave.eif

# CloudFront sends this secret as X-Origin-Verify; nginx refuses requests without it.
if [ ! -s /etc/trustgate/origin-secret ]; then
  ( umask 077; openssl rand -hex 32 > /etc/trustgate/origin-secret )
  echo "   created /etc/trustgate/origin-secret"
fi
SECRET=$(cat /etc/trustgate/origin-secret)
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
systemctl enable --now trustgate-enclave.service trustgate-forwarder.service nginx.service trustgate-watchdog.timer
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
echo "nginx:     $(curl -s -o /dev/null -w 'no origin header -> HTTP %{http_code} (expect 403)' http://127.0.0.1:8443/healthz)"
echo "origin secret for CloudFront:  sudo cat /etc/trustgate/origin-secret"
