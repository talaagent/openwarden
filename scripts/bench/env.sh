# shellcheck shell=bash
# Source me: shared settings for the benchmark scripts.
export BENCH_URL=${BENCH_URL:-https://127.0.0.1:8222}
export BENCH_EMAIL=${BENCH_EMAIL:-alice@example.org}
export BENCH_PASSWORD=${BENCH_PASSWORD:-correct horse battery staple}
export BENCH_CA=/tmp/ow-bench/tls/cert.pem
# bw (node) adds this to its trust store; ow (rustls native roots) and
# python's ssl read SSL_CERT_FILE.
export NODE_EXTRA_CA_CERTS=$BENCH_CA
export SSL_CERT_FILE=$BENCH_CA
export BW_NOINTERACTION=true
BW=${BW:-$(command -v bw || echo /etc/profiles/per-user/igm/bin/bw)}
export BW
