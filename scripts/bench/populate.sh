#!/usr/bin/env bash
# Fill the benchmark account with N synthetic logins (default 300) via bw.
#
# Usage: populate.sh [N]
# Env:   BENCH_PASSWORD (default "correct horse battery staple"),
#        BW (default: bw on PATH, else /etc/profiles/per-user/igm/bin/bw).
# Leaves a logged-in bw app-data dir in /tmp/ow-bench/bw for bench.sh.
set -euo pipefail

n=${1:-300}
url=http://127.0.0.1:8222
email=alice@example.org
export BENCH_PASSWORD=${BENCH_PASSWORD:-correct horse battery staple}
BW=${BW:-$(command -v bw || echo /etc/profiles/per-user/igm/bin/bw)}

export BITWARDENCLI_APPDATA_DIR=/tmp/ow-bench/bw
mkdir -p "$BITWARDENCLI_APPDATA_DIR"
# Keep the CLI quiet and local: no update checks, no interactive prompts.
export BW_NOINTERACTION=true

if "$BW" login --check >/dev/null 2>&1; then
  BW_SESSION=$("$BW" unlock --passwordenv BENCH_PASSWORD --raw)
else
  "$BW" logout >/dev/null 2>&1 || true
  "$BW" config server "$url" >/dev/null
  BW_SESSION=$("$BW" login "$email" --passwordenv BENCH_PASSWORD --raw)
fi
export BW_SESSION
"$BW" sync >/dev/null

folder_id() {
  local name=$1 id
  id=$("$BW" list folders --search "$name" | jq -r --arg n "$name" 'map(select(.name == $n))[0].id // empty')
  if [ -z "$id" ]; then
    id=$("$BW" get template folder | jq -c --arg n "$name" '.name = $n' | "$BW" encode \
      | "$BW" create folder | jq -r .id)
  fi
  printf '%s\n' "$id"
}
folders=("$(folder_id Work)" "$(folder_id Personal)")

existing=$("$BW" list items | jq length)
echo "vault has $existing items; creating $n logins"

template=$("$BW" get template item)
start=$SECONDS
for ((i = 0; i < n; i++)); do
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
    | "$BW" encode | "$BW" create item >/dev/null
  if (((i + 1) % 25 == 0)); then echo "  $((i + 1))/$n ($((SECONDS - start))s)"; fi
done

"$BW" sync >/dev/null
echo "done: vault has $("$BW" list items | jq length) items"
