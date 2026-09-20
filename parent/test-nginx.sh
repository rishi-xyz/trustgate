#!/usr/bin/env bash
# Tests parent/nginx-trustgate.conf with real nginx (in Docker), using a secret of
# the same length install.sh generates (64 hex characters; a short test secret once
# hid an "increase map_hash_bucket_size" failure that only appeared on the instance)
# and Cloudflare's real published address ranges (parent/testdata).
#
# A test cannot make a TCP peer look like a Cloudflare edge, so the behaviour tests
# use a second config that additionally trusts 127.0.0.1. The production include is
# tested separately: it must refuse a request from a non-Cloudflare peer even when
# the peer sends the correct secret and a spoofed CF-Connecting-IP.
#
# Needs: docker, openssl, curl, python3. Uses ports 443 and 8444 on localhost.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
cleanup() { docker rm -f tg-nginx-test >/dev/null 2>&1 || true; kill "${up:-0}" 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT
ok=0; bad=0
expect() { if [ "$2" = "$3" ]; then echo "PASS  $1 ($2)"; ok=$((ok+1)); else echo "FAIL  $1: got $2, expected $3"; bad=$((bad+1)); fi; }
code() { curl -sk -o /dev/null -m 10 -w '%{http_code}' "$@"; }

mkdir -p "$tmp/etc" "$tmp/conf.d" "$tmp/up"
secret=$(openssl rand -hex 32)
[ "${#secret}" = 64 ] || { echo "test bug: secret must be 64 chars"; exit 1; }
echo ok > "$tmp/up/healthz"
sed "s/__ORIGIN_SECRET__/$secret/" parent/nginx-trustgate.conf > "$tmp/conf.d/trustgate.conf"
TG_CERT_DIR="$tmp/etc" TG_NO_RELOAD=1 parent/origin-cert.sh csr trustgate.test >/dev/null 2>&1
export TG_CF_V4=parent/testdata/cloudflare-ips-v4.txt TG_CF_V6=parent/testdata/cloudflare-ips-v6.txt

(python3 -m http.server 8444 --bind 127.0.0.1 --directory "$tmp/up" >/dev/null 2>&1 & echo $! > "$tmp/up.pid"); up=$(cat "$tmp/up.pid"); sleep 1

run_nginx() { # $1 = generated cloudflare include
  docker rm -f tg-nginx-test >/dev/null 2>&1 || true
  docker run -d --name tg-nginx-test --network host \
    -v "$tmp/conf.d":/etc/nginx/conf.d:ro -v "$1":/etc/nginx/trustgate-cloudflare.conf:ro -v "$tmp/etc":/etc/trustgate:ro \
    nginx:alpine >/dev/null
  sleep 2
}

echo "== production include (Cloudflare ranges only)"
TG_CF_OUT="$tmp/prod.conf" parent/update-cloudflare-ips.sh >/dev/null
docker run --rm -v "$tmp/conf.d":/etc/nginx/conf.d:ro -v "$tmp/prod.conf":/etc/nginx/trustgate-cloudflare.conf:ro -v "$tmp/etc":/etc/trustgate:ro nginx:alpine nginx -t >/dev/null 2>&1 \
  && expect "config is valid with a real 64-char secret and the real ranges" ok ok || expect "config is valid" fail ok
run_nginx "$tmp/prod.conf"
expect "a non-Cloudflare peer is refused even with the right secret" "$(code -H "X-Origin-Verify: $secret" https://127.0.0.1/healthz)" 403
expect "...and even with a spoofed CF-Connecting-IP" "$(code -H "X-Origin-Verify: $secret" -H 'CF-Connecting-IP: 1.2.3.4' https://127.0.0.1/healthz)" 403

echo "== behaviour, with 127.0.0.1 treated as Cloudflare (TEST ONLY)"
TG_CF_OUT="$tmp/test.conf" TG_CF_EXTRA_TRUSTED=127.0.0.1 parent/update-cloudflare-ips.sh >/dev/null
run_nginx "$tmp/test.conf"
H="X-Origin-Verify: $secret"
expect "no secret is refused"                    "$(code https://127.0.0.1/healthz)" 403
expect "a wrong secret is refused"               "$(code -H 'X-Origin-Verify: nope' https://127.0.0.1/healthz)" 403
expect "the secret off by one character"         "$(code -H "X-Origin-Verify: ${secret%?}0" https://127.0.0.1/healthz)" "$([ "${secret: -1}" = 0 ] && echo 200 || echo 403)"
expect "half the secret is refused"              "$(code -H "X-Origin-Verify: ${secret:0:32}" https://127.0.0.1/healthz)" 403
expect "the right secret from a trusted peer works" "$(code -H "$H" https://127.0.0.1/healthz)" 200
expect "plain HTTP to the TLS port does not work" "$([ "$(curl -s -o /dev/null -m 5 -w '%{http_code}' http://127.0.0.1:443/healthz)" = 200 ] && echo 200 || echo not200)" not200
head -c 5242880 /dev/zero | tr '\0' 'a' > "$tmp/big.bin"
expect "a 5 MiB body is refused with 413"        "$(code -H "$H" -X POST https://127.0.0.1/mcp --data-binary @"$tmp/big.bin")" 413
A='CF-Connecting-IP: 203.0.113.7'
codes=$(for i in $(seq 80); do code -H "$H" -H "$A" https://127.0.0.1/healthz; echo; done | sort | uniq -c | tr '\n' ' ')
echo "      80 rapid requests as visitor A: $codes"
expect "visitor A is rate limited (429 seen)"    "$(printf '%s' "$codes" | grep -c 429)" 1
expect "visitor A stays limited right after"     "$(code -H "$H" -H "$A" https://127.0.0.1/healthz)" 429
expect "a different visitor is not affected"     "$(code -H "$H" -H 'CF-Connecting-IP: 198.51.100.9' https://127.0.0.1/healthz)" 200
expect "an IPv6 visitor address is handled"      "$(code -H "$H" -H 'CF-Connecting-IP: 2001:db8::1' https://127.0.0.1/healthz)" 200

echo "== the origin certificate helper"
E="$tmp/etc2"; export TG_NO_RELOAD=1
TG_CERT_DIR="$E" parent/origin-cert.sh csr trustgate.test >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/ca.key" -out "$tmp/ca.crt" -subj "/CN=Test CA" -days 2 2>/dev/null
openssl x509 -req -in "$E/origin.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial -out "$tmp/good.crt" -days 2 2>/dev/null
# a properly issued certificate, but for somebody else's key
openssl genrsa -out "$tmp/other.key" 2048 2>/dev/null
openssl req -new -key "$tmp/other.key" -subj "/CN=trustgate.test" -out "$tmp/other.csr"
openssl x509 -req -in "$tmp/other.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial -out "$tmp/wrongkey.crt" -days 2 2>/dev/null
inst() { if TG_CERT_DIR="$E" parent/origin-cert.sh install < "$1" >/dev/null 2>&1; then echo accepted; else echo rejected; fi; }
expect "rejects text that is not a certificate"        "$(printf 'hello' > "$tmp/junk"; inst "$tmp/junk")" rejected
expect "rejects a self-signed certificate"             "$(inst "$E/origin.crt")" rejected
expect "rejects a certificate issued for another key"  "$(inst "$tmp/wrongkey.crt")" rejected
expect "accepts a certificate issued for our key"      "$(inst "$tmp/good.crt")" accepted
expect "...and it is now the one nginx would serve"    "$(openssl x509 -in "$E/origin.crt" -noout -issuer | grep -c 'Test CA')" 1

echo "== the address updater"
# Count from the input files (Cloudflare's files have no trailing newline, so wc -l undercounts by one).
want4=$(grep -c . parent/testdata/cloudflare-ips-v4.txt); want6=$(grep -c . parent/testdata/cloudflare-ips-v6.txt)
n=$(TG_CF_OUT="$tmp/x.conf" parent/update-cloudflare-ips.sh); expect "it reports every range it was given" "$(printf '%s' "$n" | grep -c "$want4 IPv4 and $want6 IPv6")" 1
printf '<html>error</html>\n' > "$tmp/bad4.txt"
if TG_CF_OUT="$tmp/x.conf" TG_CF_V4="$tmp/bad4.txt" parent/update-cloudflare-ips.sh >/dev/null 2>&1; then r=updated; else r=refused; fi
expect "a bad download is refused" "$r" refused
expect "...and the previous file is left intact" "$(grep -c 'set_real_ip_from' "$tmp/x.conf")" "$((want4 + want6))"

echo "--- $ok passed, $bad failed"
[ "$bad" = 0 ]
