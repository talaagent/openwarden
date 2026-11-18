#!/usr/bin/env bash
# Run register.py with a Python that has `cryptography`.
#
# `nix shell nixpkgs#python3 nixpkgs#python3Packages.cryptography -c python3 -I`
# does not work: the package reaches python3 only through PYTHONPATH, which
# -I (isolated mode) ignores. A python3.withPackages env has it built in.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC2016 # Nix expression, not shell.
expr='let p = (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
in p.python3.withPackages (ps: [ ps.cryptography ])'
exec nix shell --impure --expr "$expr" -c python3 -I "$here/register.py" "$@"
