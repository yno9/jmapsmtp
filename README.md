# jmapsmtp

JMAP mail server with SMTP relay, in Rust. Bridges incoming SMTP and outgoing
SMTP delivery to a JMAP API consumed by [biset](https://github.com/yno9/biset)
or any JMAP client.

> **Status: port in progress.** This is a rewrite of
> [go-jmapsmtp](https://github.com/yno9/go-jmapsmtp) (plus the
> [go-jmapserver](https://github.com/yno9/go-jmapserver) library it depends on)
> from Go to Rust. It does not run yet. See [PLAN.md](PLAN.md) for the plan and
> [JOURNAL.md](JOURNAL.md) for the work log — both in Japanese.

## Features

- JMAP Core + Mail + Submission (`urn:ietf:params:jmap:*`)
- Multi-account, multi-domain
- Incoming SMTP server (port 25) with STARTTLS
- Outgoing SMTP delivery (MX lookup or fixed relay host)
- DKIM signing per domain
- Autocrypt key exchange (peer key storage and injection)
- PGP encryption at rest (Layer 1: server-side; Layer 2: client E2E via biset-ui)
- KEK-based auth: Argon2id + AES-GCM + HKDF (`crates/cryptenv`)
- Per-device ed25519 credentials with revocable session tokens
- DID identity binding via a standalone identity anchor (optional)
- WKD (Web Key Directory) for public key discovery
- BYO custom domains with DNS TXT ownership proof

## Layout

| Crate | Ported from |
|---|---|
| `crates/cryptenv` | `go-jmapsmtp/cryptenv` |
| `crates/jmap-types` | `git.sr.ht/~rockorager/go-jmap` (subset) |
| `crates/jmapserver` | `github.com/yno9/go-jmapserver` |
| `crates/jmapsmtp` | `github.com/yno9/go-jmapsmtp` |
| `xtask` | — (differential-test harness) |

## Build

```sh
just build           # cargo build --workspace
just build-noanchor  # equivalent of `go build -tags noanchor`
just test
just lint
```

`just --list` shows everything, including the tasks that build and check the Go
reference implementation used for differential testing (`just oracle-check`).

## Config

Copy `config.example.json` to `config.json` next to the binary and edit. The
schema is unchanged from the Go implementation, with one addition:

- `debug_dump_eml` — write every received and sent message to
  `/tmp/jmapsmtp-last-{in,out}.eml`. The Go implementation always did this;
  here it defaults to `false` because those files hold plaintext mail.

## Data layout

```
data/
  <domain>/
    key.pem           DKIM private key
    dkim-dns.txt      DNS TXT record to publish
    peers/            Autocrypt peer public keys
    <localpart>/
      setup.token     one-time setup token (deleted after first login)
      envelope.json   KEK envelope (Argon2id-wrapped master secret)
      auth_token_hash relay-scoped credential
      devices/        authorized per-device ed25519 keys
      sessions/       outstanding session tokens (hashed)
      messages/       JMAP email store
      …
```

The on-disk format is byte-compatible with the Go implementation: an existing
deployment can swap binaries in place.

## License

MIT
