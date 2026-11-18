#!/usr/bin/env bash
# Fill the benchmark account with N synthetic logins (default 300) via bw:
# site-0000.. with alice+i@example.org, random passwords, a note on every
# 5th, a TOTP secret on every 25th, spread over folders Work and Personal.
#
# Usage: populate.sh [N]
# Env:   see env.sh (BENCH_PASSWORD, BENCH_URL, BW, ...).
# Leaves a logged-in bw app-data dir in /tmp/ow-bench/bw for bench.sh.
set -euo pipefail

n=${1:-300}
# shellcheck source=env.sh
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"

export BITWARDENCLI_APPDATA_DIR=/tmp/ow-bench/bw
mkdir -p "$BITWARDENCLI_APPDATA_DIR"

if "$BW" login --check >/dev/null 2>&1; then
  BW_SESSION=$("$BW" unlock --passwordenv BENCH_PASSWORD --raw)
else
  "$BW" logout >/dev/null 2>&1 || true
  "$BW" config server "$BENCH_URL" >/dev/null
  BW_SESSION=$("$BW" login "$BENCH_EMAIL" --passwordenv BENCH_PASSWORD --raw)
fi
export BW_SESSION
"$BW" sync >/dev/null

# One `bw create item` costs ~6 s (two node start-ups plus a vault write),
# so 300 would take half an hour. Instead run one `bw serve` (the CLI's
# local REST API, bound to loopback, same session) and POST the items to it.
port=${BENCH_SERVE_PORT:-8087}
api=http://127.0.0.1:$port
"$BW" serve --hostname 127.0.0.1 --port "$port" >/dev/null 2>&1 &
serve_pid=$!
trap 'kill "$serve_pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 60); do
  curl -fsS "$api/status" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS "$api/status" >/dev/null

post() { curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$api/object/$1"; }

folder_id() {
  local name=$1 id
  id=$(curl -fsS "$api/list/object/folders" \
    | jq -r --arg n "$name" '.data.data | map(select(.name == $n))[0].id // empty')
  if [ -z "$id" ]; then
    id=$(jq -cn --arg n "$name" '{name: $n}' | post folder | jq -r .data.id)
  fi
  printf '%s\n' "$id"
}
folders=("$(folder_id Work)" "$(folder_id Personal)")

# Top up to N rather than duplicate: `get password site-0042` must stay
# unambiguous, so rerunning only adds the missing site-NNNN items.
existing=$(curl -fsS "$api/list/object/items?search=site-" \
  | jq '[.data.data[] | select(.name | test("^site-[0-9]{4}$"))] | length')
echo "vault has $existing site items; creating $((n > existing ? n - existing : 0))"

template=$("$BW" get template item)
start=$SECONDS
for ((i = existing; i < n; i++)); do
  name=$(printf 'site-%04d' "$i")
  password=$(head -c 18 /dev/urandom | base64 | tr '+/' '-_')
  notes=null totp=null folder=null
  if ((i % 5 == 0)); then notes="\"synthetic note for $name\""; fi
  if ((i % 25 == 0)); then totp='"JBSWY3DPEHPK3PXP"'; fi
  if ((i % 3 == 1)); then folder="\"${folders[0]}\""; elif ((i % 3 == 2)); then folder="\"${folders[1]}\""; fi
  jq -c \
    --arg name "$name" \
    --arg user "alice+$i@example.org" \
    --arg pass "$password" \
    --arg uri "https://site-$i.example.org/login" \
    --argjson notes "$notes" --argjson totp "$totp" --argjson folder "$folder" \
    '.type = 1 | .name = $name | .notes = $notes | .folderId = $folder
     | .login = {uris: [{match: null, uri: $uri}], username: $user,
                 password: $pass, totp: $totp}' <<<"$template" \
    | post item >/dev/null
  if (((i + 1) % 25 == 0)); then echo "  $((i + 1))/$n ($((SECONDS - start))s)"; fi
done
kill "$serve_pid" 2>/dev/null || true
wait "$serve_pid" 2>/dev/null || true

"$BW" sync >/dev/null
echo "done: vault has $("$BW" list items | jq length) items"
