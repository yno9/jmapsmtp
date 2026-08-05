# jmapsmtp

JMAP mail server with SMTP relay, in Rust. Bridges incoming SMTP and outgoing
SMTP delivery to a JMAP API consumed by [biset](https://github.com/yno9/biset)
or any JMAP client.

> **Status: complete and unproven in production.** This is a rewrite of
> [go-jmapsmtp](https://github.com/yno9/go-jmapsmtp) (plus the
> [go-jmapserver](https://github.com/yno9/go-jmapserver) library it depends on)
> from Go to Rust. It builds, runs, and answers every route the Go
> implementation does — `just difftest` compares the two binaries side by side
> over 46 requests and reports no undeclared differences.
>
> It has not been run in a real deployment. See [MIGRATION.md](MIGRATION.md)
> before switching one: a few behaviours differ on purpose, and one of them
> (`ADMIN_TOKEN`) will change what your monitoring sees.

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

## Documentation

| | |
|---|---|
| [ARC.md](ARC.md) | How it is put together, and why |
| [MIGRATION.md](MIGRATION.md) | Switching a running deployment from the Go build |
| [SPEC.md](SPEC.md) | The compatibility contract, and every deliberate difference (Japanese) |
| [PLAN.md](PLAN.md) / [JOURNAL.md](JOURNAL.md) | The porting plan and work log (Japanese) |

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
just check           # everything, including the comparison against Go
```

`just --list` shows the rest, including the tasks that build the Go reference
implementation the differential tests run against.

## How it is tested

Nothing here is checked against a reading of the Go source. Every subsystem is
compared against the Go implementation **running**:

```sh
just oracle          # build the Go binary from ~/go-jmapsmtp + ~/go-jmapserver
just difftest        # run both, same 46 requests, compare bytes
just difftest-check  # prove the harness can fail, and that the oracle agrees with itself
```

Where this port deliberately differs, the difference is asserted to **still be
there**: if the two sides ever agree, the test fails and says the divergence
was not observed. That is what catches a fix being lost in a refactor.

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
