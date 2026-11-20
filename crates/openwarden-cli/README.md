# openwarden-cli: `ow`

A fast, `bw`-compatible command-line client for
[Bitwarden](https://bitwarden.com) and
[Vaultwarden](https://github.com/dani-garcia/vaultwarden), built on the
[`openwarden`](https://crates.io/crates/openwarden) library. It's a native
binary with an encrypted local cache: `list` and `get` read the cache
offline, and `unlock` with a session key doesn't rerun the KDF.

```sh
cargo install openwarden-cli   # installs `ow`

ow config server https://vault.example.com
export BW_SESSION="$(BW_PASSWORD=... ow login alice@example.com --passwordenv BW_PASSWORD --raw)"
ow list items --search example
ow get password example.com
ow sync            # asks for the revision date first; fetches only if it moved
ow lock
```

Scripts written for `bw` mostly work unchanged. The commands, flags,
`BW_SESSION` and the JSON field names are `bw`'s. `ow` refuses secrets on
the command line where `bw` would take them (see below).

## Commands

| `bw` | `ow` |
|:---|:---|
| `config server [URL]` | yes; other settings aren't supported |
| `login EMAIL --passwordenv VAR / --passwordfile F [--raw]` | yes (stdin works too). It logs in, syncs and unlocks in one step |
| `login --apikey` (`BW_CLIENTID`, `BW_CLIENTSECRET`) | yes; then `unlock` |
| `login --sso`, two-step login | not yet |
| `unlock --passwordenv VAR [--raw]` | yes, offline |
| `lock`, `logout` | yes |
| `sync [--force] [--last]` | yes, incremental through the revision date |
| `status` | yes (`serverUrl`, `lastSync`, `userEmail`, `userId`, `status`) |
| `list items [--search] [--folderid] [--collectionid] [--organizationid] [--trash]` | yes, personal items only |
| `list folders [--search]` | yes |
| `get item\|password\|username\|totp\|notes\|uri ID-OR-SEARCH` | yes |
| `create item` (base64 JSON on stdin) | personal or organization logins: name, username, password, TOTP, URIs, folder, organizationId and collectionIds |
| `edit item ID` (base64 JSON on stdin) | logins: name, username, password, TOTP, adding URIs |
| `delete item ID [--permanent]` | yes |
| `encode` | yes |
| `generate`, `send`, `serve`, `export`, `import`, attachments, organizations | no |

`edit` refuses a change it can't make yet (notes, custom fields, the
folder, favorite, removing a URI or clearing a field), so nothing is
silently dropped. Organization items are left out of `list` and `get`, with
a note on stderr.

## Security model

- **No secrets on argv.** Other processes can read the command line. So
  `ow login EMAIL PASSWORD`, `ow unlock PASSWORD`, `--session KEY` and
  `ow create item BASE64` are refused (exit code 2). Pass the password with
  `--passwordenv`, `--passwordfile` or stdin, the session key in
  `BW_SESSION`, and item JSON on stdin.
- **Nothing in clear on disk but metadata.** The state directory is
  `$OPENWARDEN_APPDATA_DIR`, else `$BITWARDENCLI_APPDATA_DIR`, else
  `~/.config/openwarden`; it's mode 0700 and the files are 0600. Its
  `openwarden.json` holds these in clear: the server URL, a device id, the
  email, the user id, the KDF settings, the protected account key (already
  encrypted under the master key, as `bw` stores it) and the times of the
  last sync. Everything else is encrypted with authenticated AES-256-CBC +
  HMAC-SHA256 (Bitwarden's type 2):
  - the user key, under the random session key printed by `login`/`unlock`.
    `lock` deletes it, so every session key stops working;
  - a random state key, under the user key;
  - the access and refresh tokens, and the last sync response
    (`openwarden-vault.enc`), under the state key. They outlive `lock`, so
    `unlock` is offline.
- **Keys are zeroized.** Keys, tokens and decrypted output live in
  `secrecy`/`Zeroizing` buffers. Errors never quote the server's
  responses.
- `get password` and the other single values print with no trailing
  newline when stdout isn't a terminal, so `$(ow get password x)` is
  exact.

## Not yet

Organizations and collections (organization keys, RSA), two-step login,
notes, cards, identities and SSH keys in `create`/`edit`, custom fields,
`generate`, `serve`, shell completions (`ow --man` prints a manpage), and permanently deleting an item
that's already in the trash.

## License

Apache-2.0.

For organization writes, `organizationId` and `collectionIds` in the item JSON
select the target. Edits must keep the existing organization and collections;
moving an item is refused. Creation uses the organization's key from sync.
`OW_ORGANIZATION_ID` and `OW_COLLECTION_ID` supply omitted target values for
brokered runs. With `OW_REQUIRE_TARGET=1`, writes without both an organization
and at least one collection fail before making an API request. These defaults
are not access controls: the server account's collection permissions apply.
HTTP 403 means the account needs the appropriate collection write permission.

With `OW_PATCH_INPUT=1`, edits preserve omitted fields, including existing
passwords, notes and URI lists. This lets a brokered caller update a field
without reading the existing secrets. Explicit clearing and unsupported
changes are still refused; organization and collection targets must match.
