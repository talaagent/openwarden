#!/usr/bin/env bash
# Start a throwaway, volatile Vaultwarden on https://127.0.0.1:8222.
#
# It serves HTTPS with a self-signed certificate (made here, in
# /tmp/ow-bench/tls) because bw 2026.x refuses any non-https server URL and
# has no switch to allow one. Clients trust it through:
#   bw:  NODE_EXTRA_CA_CERTS=/tmp/ow-bench/tls/cert.pem
#   ow:  SSL_CERT_FILE=/tmp/ow-bench/tls/cert.pem   (rustls native roots)
#   curl/python: --cacert / cafile
# `source scripts/bench/env.sh` sets all of that.
set -euo pipefail

name=ow-bench-vw
url=https://127.0.0.1:8222
tls=/tmp/ow-bench/tls

mkdir -p "$tls"
if [ ! -s "$tls/cert.pem" ] || [ ! -s "$tls/key.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -subj "/CN=ow-bench localhost" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "$tls/key.pem" -out "$tls/cert.pem" 2>/dev/null
  chmod 644 "$tls/key.pem" # read by the container's root; throwaway key.
fi

if [ -z "$(docker ps -q --filter "name=^${name}$")" ]; then
  # A just-stopped --rm container can linger for a moment; clear it.
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --rm --name "$name" -p 127.0.0.1:8222:80 \
    -v "$tls:/tls:ro" \
    -e ROCKET_TLS='{certs="/tls/cert.pem",key="/tls/key.pem"}' \
    -e DOMAIN="$url" \
    -e SIGNUPS_ALLOWED=true -e I_REALLY_WANT_VOLATILE_STORAGE=true \
    vaultwarden/server:latest >/dev/null
fi

for _ in $(seq 1 60); do
  if curl -fsS --cacert "$tls/cert.pem" "$url/alive" >/dev/null 2>&1; then
    echo "vaultwarden up at $url"
    exit 0
  fi
  sleep 1
done
echo "vaultwarden did not come up at $url" >&2
docker logs "$name" >&2 || true
exit 1
