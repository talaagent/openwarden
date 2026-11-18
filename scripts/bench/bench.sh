#!/usr/bin/env bash
# Benchmark bw against ow on the local Vaultwarden with hyperfine.
#
# Usage: bench.sh            (after vaultwarden-up.sh, register.sh, populate.sh)
# Env:   OW (default ./target/release/ow; ow benches are skipped if missing),
#        BW, BENCH_* (see env.sh), BENCH_RUNS (optional fixed --runs).
# Both programs take the same bw-style arguments; each gets its own app-data
# dir (/tmp/ow-bench/bw via BITWARDENCLI_APPDATA_DIR, /tmp/ow-bench/ow via
# OPENWARDEN_APPDATA_DIR) and is logged in first if it isn't already.
# Writes /tmp/ow-bench/results.md.
set -euo pipefail

# shellcheck source=env.sh
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
OW=${OW:-./target/release/ow}
out=/tmp/ow-bench/results.md
work=$(mktemp -d /tmp/ow-bench/run.XXXXXX)
trap 'rm -rf "$work"' EXIT

export BITWARDENCLI_APPDATA_DIR=/tmp/ow-bench/bw
export OPENWARDEN_APPDATA_DIR=/tmp/ow-bench/ow
mkdir -p "$BITWARDENCLI_APPDATA_DIR" "$OPENWARDEN_APPDATA_DIR"

progs=(bw)
declare -A bin=([bw]=$BW)
if [ -x "$OW" ]; then
  progs+=(ow)
  bin[ow]=$(realpath "$OW")
else
  echo "note: $OW not found or not executable; skipping ow" >&2
fi

# Log in (if needed) and get a session key for each program. Keys go into
# the environment hyperfine passes down, not into the command lines, so
# they don't end up in the exported markdown. Every `bw unlock` issues a new
# session key and invalidates the old one, so this runs again after the
# unlock benchmark.
sessions() {
  local p b session
  for p in "${progs[@]}"; do
    b=${bin[$p]}
    if ! "$b" status 2>/dev/null | jq -e '.status != "unauthenticated"' >/dev/null; then
      "$b" config server "$BENCH_URL" >/dev/null
      "$b" login "$BENCH_EMAIL" --passwordenv BENCH_PASSWORD --raw >/dev/null
    fi
    session=$("$b" unlock --passwordenv BENCH_PASSWORD --raw)
    export "SESSION_${p^^}=$session"
  done
}
sessions
for p in "${progs[@]}"; do
  var=SESSION_${p^^}
  BW_SESSION=${!var} "${bin[$p]}" sync >/dev/null
done

# hyperfine 2 runs commands without a shell unless told otherwise; use bash
# (hyperfine measures and subtracts its spawn time) so the session variable
# is expanded there and the command text (and the report) stays key-free.
bench() {
  local title=$1 args=$2 needs_session=$3 p cmd
  local -a hf=(--warmup 2 --shell=bash --export-markdown "$work/part.md" --style basic)
  if [ -n "${BENCH_RUNS:-}" ]; then hf+=(--runs "$BENCH_RUNS"); fi
  for p in "${progs[@]}"; do
    cmd="$(printf '%q' "${bin[$p]}") $args"
    if [ "$needs_session" = 1 ]; then cmd="BW_SESSION=\$SESSION_${p^^} $cmd"; fi
    hf+=(--command-name "$p $args" "$cmd")
  done
  echo "== $title" >&2
  nix shell nixpkgs#hyperfine -c hyperfine "${hf[@]}" >&2
  { printf '\n## %s\n\n' "$title"; cat "$work/part.md"; } >>"$work/results.md"
}

{
  echo "# bw vs ow on a local Vaultwarden"
  echo
  echo "- date: $(date -Is)"
  echo "- server: $BENCH_URL (vaultwarden $(curl -fsS --cacert "$BENCH_CA" "$BENCH_URL/api/config" | jq -r .version)), $(BW_SESSION=$SESSION_BW "$BW" list items | jq length) items"
  for p in "${progs[@]}"; do echo "- $p: ${bin[$p]} ($("${bin[$p]}" --version))"; done
} >"$work/results.md"

bench "cold start" "--version" 0
bench "unlock" "unlock --passwordenv BENCH_PASSWORD --raw" 0
sessions
bench "list items" "list items" 1
bench "get password" "get password site-0042" 1
bench "sync (unchanged vault)" "sync" 1

cp "$work/results.md" "$out"
echo "wrote $out" >&2
