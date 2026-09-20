#!/usr/bin/env bash
# Manages the TLS certificate nginx presents to Cloudflare (SSL/TLS mode "Full (strict)").
# The private key is generated here and never leaves this machine: you paste only
# the CSR into Cloudflare, and paste the certificate it returns back here.
#
#   origin-cert.sh csr <hostname>   create the key and a CSR (plus a temporary self-signed
#                                   certificate so nginx can start), and print the CSR
#   origin-cert.sh install          read the Cloudflare Origin CA certificate (PEM) from stdin
#                                   and install it
set -euo pipefail
DIR=${TG_CERT_DIR:-/etc/trustgate}
KEY=$DIR/origin.key CRT=$DIR/origin.crt CSR=$DIR/origin.csr

case "${1:-}" in
csr)
  host=${2:?usage: origin-cert.sh csr <hostname>}
  install -d -m 700 "$DIR"
  [ -s "$KEY" ] || ( umask 077; openssl genrsa -out "$KEY" 2048 2>/dev/null )
  openssl req -new -key "$KEY" -subj "/CN=$host" -addext "subjectAltName=DNS:$host" -out "$CSR"
  if [ ! -s "$CRT" ]; then
    # Temporary, so nginx can start. Replace it with the real certificate (install).
    openssl req -x509 -new -key "$KEY" -subj "/CN=$host" -addext "subjectAltName=DNS:$host" -days 30 -out "$CRT"
    echo "created a temporary self-signed certificate (valid 30 days); replace it with the Cloudflare one" >&2
  fi
  cat "$CSR"
  ;;
install)
  [ -s "$KEY" ] || { echo "no private key at $KEY: run 'csr' first" >&2; exit 1; }
  tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
  cat > "$tmp"
  openssl x509 -in "$tmp" -noout 2>/dev/null || { echo "that is not a PEM certificate" >&2; exit 1; }
  want=$(openssl pkey -in "$KEY" -pubout 2>/dev/null | openssl sha256)
  have=$(openssl x509 -in "$tmp" -noout -pubkey | openssl sha256)
  [ "$want" = "$have" ] || { echo "this certificate was not issued for the private key on this machine (was it made from the CSR printed by 'csr'?)" >&2; exit 1; }
  # Self-signed: the issuer name is the subject name (compare hashes; the text forms
  # carry different "subject="/"issuer=" prefixes and would never match).
  if [ "$(openssl x509 -in "$tmp" -noout -subject_hash)" = "$(openssl x509 -in "$tmp" -noout -issuer_hash)" ]; then
    echo "refusing to install a self-signed certificate" >&2; exit 1
  fi
  install -m 644 "$tmp" "$CRT"
  echo "installed: $(openssl x509 -in "$CRT" -noout -subject -issuer -enddate | tr '\n' ' ')"
  if [ "${TG_NO_RELOAD:-}" != 1 ] && systemctl is-active --quiet nginx; then
    nginx -t && systemctl reload nginx && echo "nginx reloaded"
  fi
  ;;
*) echo "usage: origin-cert.sh csr <hostname> | install  (certificate PEM on stdin)" >&2; exit 2 ;;
esac
