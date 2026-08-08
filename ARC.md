# jmapsmtp Architecture

How this relay is put together, and why in these particular ways. For the
compatibility contract with the Go implementation see [SPEC.md](SPEC.md); for
the porting plan and work log see [PLAN.md](PLAN.md) and [JOURNAL.md](JOURNAL.md)
(both Japanese).

---

## 1. What it is

An SMTP↔JMAP bridge. Mail arrives on port 25 and is stored; a client reads and
sends it over JMAP; outbound mail leaves over SMTP.

The part that makes it unusual is **who a user is**.

---

## 2. Identity is the DID, not the address

A user's identity — and therefore their inbox — rests on their **DID**. The
address is a routing label that DID holds a claim on.

```
DID root key
  └─ vouch:   devkey:<did>:<devicePubKey>:<label>:<ts>     signed by the root key
       └─ device key            <acct>/devices/<pubkey>.json
            └─ session: session:<did>:<devicePubKey>:<ts>  signed by the device
                 └─ session token   <acct>/sessions/<hash>.json
```

Three consequences run through the whole design:

- **The relay stores no DID.** Which addresses trace back to which identity is
  cross-relay information the anchor derives from the claim. A local copy is
  what drifted out of step with the registry before (`provision.go`), and this
  port does not reintroduce one.
- **`did:dht` and `did:webvh` are not interchangeable.** A `did:dht` identifier
  *is* the root public key, so a vouch verifies with no network — an anchorless
  relay can serve those. A `did:webvh` SCID is
  `base58btc(multihash(JCS(genesis log entry)))`: it self-certifies the DID
  *document log*, not a signing key, so only the anchor can resolve one.
- **The signed statements are shared with the client byte for byte.** Three
  implementations — biset, this relay, the anchor — agree on two strings.

The strings come from biset's `src/did/devicebind.ts`, and matching them is
verified rather than assumed (`crates/jmapserver/src/diddht.rs`).

---

## 3. Crates

| Crate | Ported from | Holds |
|---|---|---|
| `crates/cryptenv` | `go-jmapsmtp/cryptenv` | The password envelope: Argon2id + AES-GCM + HKDF |
| `crates/jmap-types` | `git.sr.ht/~rockorager/go-jmap` | The JMAP types, and Go's JSON encoding |
| `crates/jmapserver` | `github.com/yno9/go-jmapserver` | The JMAP store, methods, MIME, device keys, anchor protocol |
| `crates/jmapsmtp` | `github.com/yno9/go-jmapsmtp` | The relay: SMTP both ways, HTTP routes, delivery |
| `xtask` | — | The differential harness |

The layering is the Go original's, and it is load-bearing: `jmapserver` knows
nothing about SMTP, so a change to delivery cannot reach the store's wire
format without going through a crate boundary.

### Why `jmap-types` has its own JSON encoder

Go's `encoding/json` **HTML-escapes by default** — `<`, `>`, `&`, U+2028,
U+2029 — and sorts map keys. Mail is full of angle brackets (`inReplyTo` is
`<id@host>`) and ampersands. `serde_json` emits all five raw, so every stored
message would differ by bytes from one the Go build wrote.

`jmap_types::go_json` is the only encoder used on any path that writes to disk
or to a client (SPEC.md §4).

---

## 4. Routing is Go's `ServeMux`, not axum's

axum carries HTTP/1.1; `crates/jmapsmtp/src/gomux.rs` does the routing. Three
reasons, and the first is not a detail:

1. **Registering a pattern twice panics at startup.** That is the production
   incident `route_registration_test.go` guards: two registration functions
   claimed `/account/devices`, and `ServeMux` killed the relay on deploy. axum
   accepts the duplicate silently, so porting to it would lose the crash *and*
   keep the bug.
2. **Subtree patterns.** `/jmap/api/` matches `/jmap/api/anything/at/all` and
   the handler splits the remainder. axum would 404.
3. **The redirects.** `/jmap/api` → `/jmap/api/`, `//relay-info` →
   `/relay-info`, both 307 with the query carried over.

The redirect status is **307 in Go 1.26 and 301 in Go 1.22**. This port follows
the toolchain the oracle is built with, established by asking the running
binary — reading the Go source on the build machine would have given the wrong
answer.

---

## 5. The startup sequence is ordered

`main.rs` follows SPEC.md §2. Two orderings are contracts rather than
preferences, and both are named at the call site:

- **The dynamic domain registry loads before the orphan sweep.** A custom
  domain verified in an earlier run exists only in `data/_domains/`; sweeping
  first deletes the mail of every account on it.
- **SMTP binds before HTTP**, and the bind is awaited. A relay that accepts
  JMAP but not mail is worse than one that is not up yet, because monitoring
  reads it as healthy. Go starts SMTP in a goroutine and serves HTTP from the
  main one, so it has a window where exactly that is true — measured at
  roughly one connect in three (SPEC.md §11.18).

An account exists **iff** it has an `auth_token_hash` **or** a device key —
never by `envelope.json`, which a third-party or DID-only account does not
have. The sweep and the recovery scan use the same rule; if they disagreed, one
would delete what the other restores.

---

## 6. Two copies of every sent message

The recipient gets the plaintext. What stays on the relay is sealed to the
account's own public key, so the relay cannot read its users' sent mail.

```
Email/set create   → draft, in memory only (lost on restart, by design)
EmailSubmission/set → stored copy: sealed          ─┐ built from one message,
                    → outbound copy: plaintext     ─┘ diverging before either leaves
```

Sending the sealed copy would deliver ciphertext to someone with no key for it;
storing the plaintext would defeat the sealing. With no key on file the stored
copy is plaintext — the relay has to keep *something*, and uploading a key is
what turns that off.

The build-and-sign order is a contract too, because each step signs or wraps
what the previous produced:

```
build RFC 5322 → Autocrypt → Chat-Version → PGP/MIME wrap → DKIM → send
```

DKIM is last. A header added after it invalidates the signature, and swapping
two steps does not error — it produces a message that fails verification at the
far end.

---

## 7. Everything remote sits behind a trait

| Trait | Decides |
|---|---|
| `smtp_out::MxResolver` | where a message goes |
| `dns::TxtResolver` | whether someone controls a domain |
| `anchor::Transport` | whether a DID proof is good |
| `smtp_in::Backend` | what happens to a received message |

Not for abstraction's sake: each of these decides something consequential, and
a trait is what lets the decision above it be tested without asking the
internet. The defaults all **fail closed** — a resolver that answers nothing
refuses every ownership proof, rather than accepting during an outage.

---

## 8. How the port is known to be right

Never by reading the Go source and believing it. Every subsystem is compared
against the Go implementation **running**:

- **`just difftest`** — the oracle and this port, same scenario, 46 steps,
  compared byte for byte including headers.
- **Interop suites** — per module, driving the oracle's real endpoints or Go
  helper programs linked against the real packages.
- **`just difftest --self-test`** — the harness proving it can fail, by
  mutating the oracle.
- **`just difftest-noanchor`** — the same 49 steps against the *anchorless*
  pair: `go build -tags noanchor` versus `cargo build --no-default-features`.
  A whole build configuration that had never been compared.
- **`no_route_answers_501`** — walks the route table and fails on any pattern
  with no handler behind it. Three shipped; each was found by a person using
  the relay, not by a test, because each comparison above missed it for a
  different reason.

`just check` runs all of it.

`just bench` is the same idea applied to speed: both binaries booted from the
identical fixture, 1,000 messages delivered into each over SMTP, then the same
requests timed on both. It is **not** in `check` — timings are noisy, and a
machine having a bad minute must not fail the acceptance run.

On one idle machine this port starts in about two-thirds of Go's time, sits on
less memory, and is faster on every route measured.

`Email/query` over 1,000 messages was the exception, at 0.83× — **slower** than
Go. The cause was a straight translation that costs the two languages very
different amounts: `Store::all()` clones every message, and in Rust that clone
is *deep*, a fresh allocation per header string and per map, where Go's copy of
the same struct duplicates slice and string headers and not the bytes. Query
wants only the ids. `Store::matching_ids` filters under the read lock and
clones nothing else: 2.17ms → 0.70ms, and resident memory fell with it because
a query no longer allocates the whole mailbox.

The order it returns has to match `all()` exactly, ties included, since a
client pages through it — both iterate the `BTreeMap` in key order and both
sort **stably** on the negated timestamp. The test that pins this needed 60
messages before an unstable sort would misorder any of them; at five it passed
against a deliberately broken sort.

Getting there took two corrections worth knowing about, because both made the
bench report a number that meant nothing:

- The fixture seeds no messages, so the first version timed `Email/query`
  against an empty mailbox and called it "the store's sort and filter path".
  It was measuring the same thing `relay-info` measures.
- Delivering 1,000 in one connection left the oracle holding 256 (§11.17) and
  this port holding 1,000 — two different benchmarks under one name. Delivery
  is batched around Go's buffer now, and the mailbox count is checked against
  what was sent before anything is timed.

### Declared divergences

Where this port deliberately differs, the difference is **asserted to still be
there**. If the two sides ever agree, the test fails and says the divergence
was not observed — which is what catches a fix being lost in a refactor. They
are listed in SPEC.md §11; the ones that matter most:

| | |
|---|---|
| §11.13 | An unset `ADMIN_TOKEN` opens every admin route in Go. Here it closes them. |
| §11.14 | Go's sealed stored copy leaves the HTML alternative in plaintext. |
| §11.15 | Go's WKD serves the **relay's** key for a capitalised `?l=`, not the user's. |
| §11.16 | Go's account metric and account listing disagree with each other. |
| §11.17 | Go buffers inbound mail in a 256-slot channel drained only by a JMAP request, and **discards** the overflow after answering `250`. Here mail is stored on arrival. |
| §11.18 | Go can answer JMAP before its mail port is bound. Here it cannot. |

---

## 9. What is not here

- **A DHT node.** `/pkarr/` forwards a client's `did:dht` record to the
  anchor's node rather than running one. Every relay used to run its own — its
  own UDP socket, routing table and republish loop, duplicated per relay. The
  route stays because the *client's* route stays: biset derives its gateway URL
  from its own relay and publishes only there, so removing it would strand
  every loaded client.

  `PUT /account/did` and `/pkarr/` were in this list as **unimplemented**, and
  *how that got missed* is worth keeping, because it is a failure of the method the rest of
  this document argues for. `mux_interop` compares route **tables** and both
  sides list the route. `server_interop`'s list of unwired routes had been
  emptied, and an empty array makes its loop run zero times, so it asserted
  nothing. The difftest scenario never requested the path. Three layers of
  comparison, and the gap sat in the seam between them — found by deploying the
  relay and watching a client get 501.

  The seam is closed rather than patched: `did_bind_interop` stands up a stub
  anchor and runs **both** implementations against it, which is a comparison
  that did not exist before — every interop suite until then ran an anchorless
  oracle, so the anchored surface had never been compared at all. It also runs
  an anchorless pair, because the order of the checks is only observable there.


- **The anchor itself.** An external service; this relay is a client.
- **Layer 2 encryption.** biset's client encrypts before submitting; the relay
  wraps and forwards.
- **Blob upload/download.** `NewMux` mounts `/jmap/upload/` and
  `/jmap/download/` only if the handler implements `BlobHandler`, and the
  relay's does not. Asked of the running oracle: mounted routes answer 401
  unauthenticated, these two answer 404 like an unregistered path.

  The session document still advertises `uploadUrl` and `downloadUrl`, because
  `NewMux` fills them unconditionally. This port advertises the same two
  unreachable URLs — a client that already copes with Go's session must keep
  coping, and `server_interop` asserts both fields match.

---

## 10. Reading order

`SPEC.md` first if you are changing behaviour — it records what cannot be seen
from the code. Then the module headers: each says what it is for and which
decisions in it are load-bearing.
