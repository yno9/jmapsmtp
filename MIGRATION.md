# Migrating a deployment from go-jmapsmtp

This port reads and writes the same `data/` directory and the same
`config.json` as [go-jmapsmtp](https://github.com/yno9/go-jmapsmtp). Switching
is replacing the binary.

What follows is what to check before doing that, and the handful of places
where behaviour deliberately differs.

---

## Before you switch

### 1. Set `ADMIN_TOKEN` and `METRICS_TOKEN`

**This is the change most likely to break something.**

Go's `bearerAuth` skips the check entirely when the token is empty, so a relay
started without these serves `/admin/*` and `/metrics` to anyone who can reach
the port. Verified against the running Go binary: `GET /admin/accounts` returns
the full list of provisioned addresses unauthenticated, and
`POST /admin/drain-anchor` — which releases every claim the relay holds at the
anchor — reaches its handler.

This port treats a missing token as **closed** (SPEC.md §11.13).

So: if you scrape `/metrics` with no `METRICS_TOKEN` set, that scrape starts
getting 401s the moment you switch. Set the variables and update the scraper
first, and the switch changes nothing:

```sh
ADMIN_TOKEN=… METRICS_TOKEN=… ./jmapsmtp
```

If you were relying on the admin routes being open, they were open to everyone.

### 2. Check `config.json` against the anchor rule

Startup refuses a config with `anchor_url` set and `anchor_token` empty — the
same refusal Go makes. Nothing new, but worth confirming before a restart
rather than during one.

The shipped `config.example.json` in the Go repository does not start, for this
reason and because its account keys are full addresses where a localpart
belongs. The copy here is corrected (SPEC.md §11.12); if you started from the
Go example, check yours.

### 3. Take a backup of `data/`

Ordinary caution. The formats are identical and the startup sweep uses the same
keep-rules, but a relay that has been running for a while accumulates shapes
nobody planned.

---

## Switching

```sh
cargo build --release              # or --no-default-features for -tags noanchor
systemctl stop jmapsmtp
cp target/release/jmapsmtp /path/to/jmapsmtp
systemctl start jmapsmtp
```

The binary reads `config.json` **from its own directory**, not the working
directory — the same as Go.

### The anchorless build

`cargo build --no-default-features` is this port's `go build -tags noanchor`.
It mounts no `/account/did`, no `/pkarr/`, and no `/admin/drain-anchor`, and
refuses to create a `did:webvh` account — the same as the Go tag.

---

## What changes

Everything below is deliberate, recorded in SPEC.md §11, and asserted by a test
that fails if the difference ever disappears.

| | What you will notice |
|---|---|
| **§11.13** | `/metrics` and `/admin/*` answer 401 without a token. See above. |
| **§11.14** | The stored copy of a sent message no longer keeps the HTML alternative in plaintext. Sealed messages are now actually sealed; nothing you can see changes except that the plaintext is gone. |
| **§11.15** | A WKD lookup with a capitalised `?l=` returns **the user's** key instead of the relay-wide one. In Go the sender encrypted to a key the relay holds and the user does not. |
| **§11.16** | `biset_accounts` no longer counts `peers` or the domain registry, and `/admin/accounts` no longer lists `<domain>@_domains`. **Your account count will drop** by one per domain holding peer keys plus one per registered custom domain. It was inflated before. |
| **§11.1** | `/tmp/jmapsmtp-last-{in,out}.eml` is written only with `"debug_dump_eml": true`. Go writes it always; it holds plaintext mail. |
| **§11.2** | A malformed `envelope.json` is rejected on read rather than accepted and failing later. |
| **§11.17** | Under a burst, Go **loses mail**: inbound messages go into a 256-slot buffer drained only when a JMAP request arrives, and anything past it is discarded after the sender was told `250`. Here mail is stored on arrival. You will not see this change — you will stop losing mail you never knew you were losing. |
| **§11.18** | Go can answer JMAP for a moment before its SMTP port is bound; here the mail port is up first. If your health check tests HTTP only, it was briefly lying to you. |
| **§11.11** | A message whose PGP markers are reversed no longer takes the process down. In Go this is a remote crash: one message stops the relay for every account. |

Two smaller ones with no operational effect: map-iteration order is now stable
where Go's varies (§11.5), and `Mailbox/set` no longer loses data on a partial
failure (§11.7).

### Metrics

The `biset_*` series are identical apart from §11.16. The Go build also exports
Go-runtime and process collectors (`go_*`, `process_*`) which describe the Go
process and have no counterpart here. **Those series disappear.** If you alert
on `go_goroutines`, that alert stops firing rather than going critical — check
your dashboards.

---

## Rolling back

Stop, put the Go binary back, start. The data directory is unchanged in any way
the Go build cannot read: every format is compared byte for byte in both
directions by the interop suites, including device keys, session tokens,
envelopes, contacts, the activity log and stored messages.

Two things to know:

- **Accounts created under this port work in Go.** Provisioning writes the same
  device key and no `auth_token_hash`, which is what the Go flow writes too.
- **Sealed messages stay sealed.** A message whose stored copy this port
  encrypted is readable by the account's key, which is where it was always
  readable from. The Go build will not re-add the HTML plaintext it used to
  leave.

---

## Verifying the switch yourself

The comparison this port is built against is reproducible:

```sh
just oracle        # builds the Go binary from ~/go-jmapsmtp + ~/go-jmapserver
just check         # lint, tests, the harness self-test, then oracle vs this port
```

`just difftest` alone runs the two binaries side by side over 49 requests and
compares status, headers and body. A difference it does not already declare is
a bug in this port.
