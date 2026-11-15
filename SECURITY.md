# Security policy

openwarden handles master passwords, API keys, vault keys and decrypted
vault data, so security reports are welcome and taken seriously.

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/talaagent/openwarden/security/advisories/new).
If that form is unavailable, email **github@igm.pub**. Please do not disclose
an unpatched vulnerability in a public issue or pull request.

Include the affected version, the server (Bitwarden cloud, self-hosted
Bitwarden or Vaultwarden, and its version), the impact, and a minimal
reproduction. Use a throwaway account and synthetic items. Never send real
master passwords, API keys, access tokens, protected keys, sync responses or
vault exports, in a report or anywhere else.

## Supported versions

Fixes go into the latest published release. Before 1.0, that is the latest
0.x minor version; older versions don't get backports.

## Scope

In scope, for example:

- a key, token, password or other decrypted value that leaks through
  `Debug`, `Display`, an error, a log line or a panic message;
- decryption without verifying the MAC, or accepting an unauthenticated
  `EncString` type;
- a way around `KdfPolicy` (a server forcing weaker or unbounded KDF
  parameters);
- URI matching that offers a login to a page it shouldn't, given the
  documented match rules and the default `MatchOptions`;
- a write that changes an item without a matching `ConfirmedItem`;
- plain HTTP to a non-loopback host, following a redirect with the bearer
  token, or reading a response body past the configured cap;
- a panic, unbounded memory or unbounded time on a crafted server response.

Out of scope:

- the documented trust in the server to keep each encrypted field with its
  item (see "Security model" in the README): Bitwarden's format doesn't
  bind fields to items, so a hostile server can swap them;
- copies of secrets made inside dependencies (reqwest, hyper, rustls) or by
  the calling application after it exposes a secret;
- vulnerabilities in Bitwarden or Vaultwarden themselves: report those to
  [Bitwarden](https://github.com/bitwarden/server/security/policy) or
  [Vaultwarden](https://github.com/dani-garcia/vaultwarden/security/policy);
- a vulnerability in a dependency, unless openwarden's use of it makes it exploitable
  (report it upstream too).
