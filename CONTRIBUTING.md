# Contributing

Bug reports, documentation fixes, test cases and pull requests are welcome.
For a bug, include the crate version, the server (Bitwarden cloud,
self-hosted Bitwarden or Vaultwarden, and its version) and the smallest
reproduction you can, using a throwaway account and synthetic items. Never
post real passwords, API keys, tokens or sync responses. Report security
issues privately (see [SECURITY.md](SECURITY.md)).

Keep pull requests small and focused, with a commit subject that reads well
as a changelog line (release-plz builds CHANGELOG.md from them). The
layout and the rules for secrets, errors, logging and test data are in
[AGENTS.md](AGENTS.md).

## Checks

Rust 1.88 is the minimum. The Nix dev shell provides the toolchain,
cargo-nextest, cargo-deny and OpenSSL:

```sh
nix develop -c cargo fmt --all --check
nix develop -c cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
nix develop -c cargo nextest run --workspace --all-targets --all-features --locked
nix develop -c cargo test --workspace --all-features --doc --locked
RUSTDOCFLAGS="-D warnings" nix develop -c cargo doc --workspace --no-deps --all-features --locked
nix develop -c cargo deny check
```

The tests need no account or network: a local mock server stands in for
the API. CI also builds and tests on the MSRV, runs
`cargo publish --dry-run` and `nix flake check`, and regenerates the
known-answer fixtures to check they are unchanged:

```sh
nix develop -c bash scripts/gen-fixtures.sh | diff -u crates/openwarden/tests/fixtures/kat.json -
```

## Releases

`release-plz.toml` writes CHANGELOG.md and tags `v<version>` with a GitHub
release. openwarden-cli shares the workspace version and is released with
the library, with its own changelog (`crates/openwarden-cli/CHANGELOG.md`),
an `openwarden-cli-v<version>` tag and a GitHub release. With `release_always = false`, only a merged release PR
publishes. Review the version bump (cargo-semver-checks runs on the
release PR) and the changelog, and merge only after CI passes.

The release-plz workflow runs only on the public `talaagent` repository.

Release PRs use the built-in `GITHUB_TOKEN` by default, with job-level
`contents: write` and `pull-requests: write` permissions. Enable **Allow
GitHub Actions to create and approve pull requests** in the organization and
repository Actions settings, then set the repository variable
`RELEASE_PR=true`. The workflow dispatches CI for those PRs itself (with
`actions: write`), because events from `GITHUB_TOKEN` don't trigger
workflows. An optional `RELEASE_PLZ_TOKEN` secret (GitHub App token or PAT)
replaces the built-in token.

### First publication

Trusted publishing can't create a crate, so the first release needs a
token:

1. Create a short-lived crates.io token with the `publish-new` scope and
   store it as the `CARGO_REGISTRY_TOKEN` Actions secret.
2. Add the release date to the `0.1.0` heading in CHANGELOG.md.
3. Run the release-plz workflow by hand with `bootstrap=true`. It
   publishes the committed version.
4. On crates.io, add a trusted publisher to the crate: owner `talaagent`,
   repository `openwarden`, workflow `release-plz.yml`, no environment.
5. Delete the `CARGO_REGISTRY_TOKEN` secret and revoke the token. Later
   releases use OIDC; a persistent token would override it.

Afterwards, check the crate's page on crates.io and its docs.rs build.

## License

Contributions are licensed under Apache-2.0, like the project.
