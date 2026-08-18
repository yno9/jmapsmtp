# jmapsmtp Architecture

How this relay is put together, and why in these particular ways. For the
compatibility contract with the Go implementation see [SPEC.md](SPEC.md); for
the porting plan see [PLAN.md](PLAN.md) (both Japanese).

---

## 1. What it is

An SMTP↔JMAP bridge. Mail arrives on port 25 and is stored; a client reads and
sends it over JMAP; outbound mail leaves over SMTP.

The part that makes it unusual is **who a user is**.

---

## 2. Identity and account lifecycle

Everything from "who may create an account" to "how a single request proves
who it is from" is gathered here as one section rather than left scattered by
file, because it is one design, not eight unrelated features: **the DID owns
the account, and every credential below it — device key, session token,
alias — is just something that DID vouched for.** §2.1–2.2 are the identity
model itself; §2.3–2.8 are what it implies for account creation, binding,
existence, aliasing, the anchor, and the route table, in the order a request
actually passes through them.

The code matches this on disk (2026-08-18): every module this section
describes lives under `crates/jmapserver/src/did/` and
`crates/jmapsmtp/src/did/`, not scattered by feature across each crate's root.
This relay is a plain JMAP server first — most of it neither knows nor cares
whether an account is DID-backed — and `did/` is the whole of what "and
did:webvh-aware" adds on top; each crate's `did.rs` says so directly, and is
the reading-order entry point this section's own order follows.

### 2.1 Identity is the DID, not the address

A user's identity — and therefore their inbox — rests on their **DID**. The
address is a routing label that DID holds a claim on. Three consequences run
through the whole design:

- **The relay stores no DID.** Which addresses trace back to which identity is
  cross-relay information the anchor derives from the claim. A local copy is
  what drifted out of step with the registry before (`provision.go`), and this
  port does not reintroduce one.
- **Every binding needs the anchor.** A `did:webvh` SCID is
  `base58btc(multihash(JCS(genesis log entry)))`: it self-certifies the DID
  *document log*, not a signing key, so only the anchor can resolve one. This
  relay therefore does not verify vouch signatures at all — it decides *who to
  ask*, not *whether they are good*.

  It used to. `did:dht` was the exception: the identifier *is* the root public
  key, so a vouch verified with no network and an anchorless relay could serve
  those accounts. biset moved to `did:webvh` alone and the method went with it
  (SPEC.md §11.27), taking that shortcut and the `/pkarr/` gateway. The Go
  implementation still has both, which makes this the widest declared
  divergence in the port.
- **The signed statements are shared with the client byte for byte.** Three
  implementations — biset, this relay, the anchor — agree on them (§2.2).

### 2.2 The credential chain: root key → device key → session

```
DID root key
  └─ vouch:   devkey:<did>:<devicePubKey>:<label>:<ts>                          signed by the root key
       └─ device key            <acct>/devices/<pubkey>.json
            └─ session: session:<did>:<devicePubKey>:<relayHost>:<nonce>:<ts>   signed by the device
                 └─ session token   <acct>/sessions/<hash>.json
```

The two signed statements come from biset's `src/did/devicebind.ts`, and
matching them is verified rather than assumed
(`crates/jmapserver/src/did/devicebind.rs`, named after it — it held the
statements *and* did:dht until the method was removed, and that misfiling is
why the removal first looked as though it would take device binding with it).

The session statement carries two segments the vouch statement doesn't
(SPEC.md §11.28, 2026-08-16):

- **`relayHost`** — without it, a device signature captured by one relay
  verifies just as well replayed against a DIFFERENT relay the same device is
  also registered with.
- **`nonce`** — `relayHost` alone stops a cross-relay replay but not a
  same-relay one inside the freshness window (`devicebind::FRESHNESS_WINDOW`,
  300s): a captured signature POSTed again to the SAME relay still verifies on
  `ts` alone. A single-use nonce from `GET /account/session/challenge`
  (`did/session_nonce.rs`) closes that — consumed on first use, so a replay fails
  because the nonce is already spent, however fresh `ts` still is.
  Deliberately not bound to any account or device: the challenge endpoint
  itself is uncredentialed (next point), so tying the nonce to an identity
  would add no protection the signature doesn't already provide, and the
  in-memory set isn't persisted — at a 60s TTL, a restart loses nothing worth
  keeping.

Four routes carry this at runtime (`did/devices.rs`), and which ones require an
existing credential is not uniform, on purpose:

| Route | Guard | Why |
|---|---|---|
| `GET /account/session/challenge` | none | issues the nonce login needs; a nonce authorises nothing by itself |
| `POST /account/session` (login) | none — the device signature *is* the credential | replaces a static bearer with something that expires and can be revoked per device |
| `POST /account/devices` (vouch a new device) | none — the vouch signature *is* the credential | this is what makes fully cold recovery possible: mnemonic only, fresh install, no prior session to authenticate with |
| `GET`/`DELETE /account/devices` | `authenticate()` | listing/revoking acts on an account that already exists, so the caller must already hold one of its credentials |

All four share one route pattern and dispatch on method inside
(`server.rs::account_devices`) — splitting them by pattern is the exact
production incident `gomux.rs`'s header describes.

### 2.3 Three ways to open a domain to self-service creation

`DomainConfig` has three modes, checked in this strictness order
(`did/provision.rs::may_provision`) because each is a stronger, more specific
statement than the one after it:

1. **`authorized_did_domain`** — admits identities by where their `did:webvh`
   is rooted, and holds them to their own name: `did:webvh:{scid}:{that
   domain}:{username}` may have `{username}@{this mail domain}`, nothing
   else. The check is a string parse and two comparisons
   (`did/webvh_id.rs`/`did_domain_gate`) — no anchor round trip, no network. When
   set, it is the **only** thing consulted: an operator who named a domain
   they trust said something more specific than "open", and letting
   `allow_provision` also be true would silently discard that.

   **It is `Option<String>`, never `Vec<String>`.** A mail domain names AT
   MOST ONE did-domain. This is not a limitation worked around elsewhere — it
   is what makes the mode need no separate claim registry: with exactly one
   did-domain per mail domain, the `did:webvh` log store's own
   append-only-per-(domain,username) shape already IS the non-duplication
   guarantee (one log per name, first writer wins). A list of N did-domains
   sharing one mail domain would reopen the gap a registry exists to close —
   two different did-domains could both mint an `alice`, and something would
   have to decide, first-come, which `alice@here` actually is. Pinning 1:1 is
   what lets that something be "nothing" instead of a new stateful service.

   Configured as an explicit pair per mail domain — `config.example.json`:

   ```json
   "domain": {
     "biset.md":   { "authorized_did_domain": "biset.md" },
     "t.biset.md": { "authorized_did_domain": "t.biset.md" }
   }
   ```

   **The relay's own domain is not implicit.** `biset.md` admits `biset.md`
   identities because it says so, same value on both sides — there is one
   rule, and "my own domain" is not a special case of it. A future
   third-party domain — some operator's `example.com` identities landing on
   this relay's `example.biset.md` — is the identical shape, one more pair,
   not a different code path
   (`the_relays_own_domain_is_not_implicitly_authorized`,
   `an_identity_from_the_named_domain_may_have_its_own_name` in
   `provision/tests.rs`).

   That third-party case is not yet reachable end to end: this relay resolves
   `did:webvh` documents by asking its own anchor (§2.7), and the anchor today
   only serves logs it hosts itself. A pair naming a domain the anchor does
   not host cannot be verified — `authorized_did_domain` will accept the
   config, but every provision against it fails at the anchor's resolve, not
   silently. Making that case real needs the anchor to resolve an ARBITRARY
   did-domain's log over HTTPS (not just its own store), which needs its own
   SSRF posture before it is safe to point at operator-supplied domains —
   tracked, not yet built.

2. **`allow_provision`** — open to anyone.
3. **`provision_secret`** — open to anyone holding the string. An empty
   secret must never match an empty submitted one.

A domain with none of the three set is not creatable at all, which is how a
privileged domain is configured on purpose.

Two more rules `POST /account/provision` (`server.rs::account_provision`)
enforces regardless of which mode admitted the request:

- **`name_is_taken` checks both credential shapes** — `auth_token_hash` (the
  older static credential) and a `devices/` entry (what this flow itself
  writes). Checking only one hands an existing account to whoever asks for
  it next.
- **The account cannot exist without a working device credential.** The vouch
  is verified and written *before* the account is registered
  (`did/provision.rs`'s own header), so there is no "create now, add a device
  later" gap for someone else to walk into.
- **Every DID method needs the anchor now.** `did:dht`'s identifier was its
  own root key, so a vouch verified locally with no anchor at all
  (`provision::VouchPath::Local`, since removed). A `did:webvh` root key
  lives only in a resolved log — an anchorless relay says so and refuses,
  rather than silently accepting an unverifiable vouch.

### 2.4 Binding a DID after the fact

`PUT /account/did` (`did/bind.rs`, `server.rs::account_did`, anchor build
only) is the lazy-migration path: an address provisioned before this relay
knew about DIDs binds one on next login, rather than never getting one.

- **The target account comes only from Basic Auth, never the body.** Taking it
  from the body would let anyone with a self-service account bind a DID to
  somebody else's address.
- **Basic Auth and `did_sig` prove two different things.** Basic Auth proves
  the caller owns the *account*; it says nothing about whether they own the
  *DID* they're naming. Before `did_sig` was required, any self-service
  account could have a stranger's DID bound to it, and the anchor would then
  publish a claim asserting that — owning an account was never evidence of
  owning an identity.
- **An anchorless relay answers `no identity anchor` before it even looks at
  `did_sig`** (`did_bind::decide`'s explicit ordering) — the missing
  signature isn't the caller's real problem when nothing they send would work
  anyway. This used to answer `204` instead, reporting success for work it
  had neither done nor could do; the caller treating the call as best-effort
  was never license to lie to it.

The anchor is the one that judges the proof (§2.7's `verify_binding`/`claim`)
— this relay only carries it, same "decide who to ask, not whether they're
good" split as §2.1.

### 2.5 What "an account exists" means

Two files sit in every account directory (`auth_env.rs`):

```
<acctDir>/auth_token_hash   base64(sha256(scoped token))  — what login checks
<acctDir>/envelope.json     cryptenv.Envelope             — the client's key material
```

They are separate on purpose. The envelope carries its own token hash, but
login never uses it: that token is scoped per relay, so one stolen from
another relay is useless here — and an account with no envelope at all (a
DID-less or third-party account) still has to be able to log in.

**An account exists iff `auth_token_hash` exists.** Every existence check in
the relay uses that file and never `envelope.json` (SPEC.md §2) — an account
created by the signature flow (§2.2) has no envelope, and treating the
envelope as the marker 404s it.

This rule used to read "`auth_token_hash` **or** a device key". Neither
implementation actually does that, and the difference is not academic: a
production relay was found holding an account with a device key, sessions and
PGP keys but no `auth_token_hash`, which **both** binaries delete on their
next start-up under the narrower rule. Go's rule is reproduced here (§5 uses
it too, for the startup sweep and the recovery scan); whether to diverge from
it is SPEC.md's question, not this document's, but a description that
flatters the code is worse than none.

`authenticate()` (`auth_env.rs`) checks a session token from device login
first, then falls back to the static `auth_token_hash` — and confirms the
account is configured or dynamically registered **before** the static check,
not after: skipping that ordering would authenticate any `<anything>@domain`
whose directory merely happens to exist.

### 2.6 Aliases: SCID-primary and the reconcile backstop

A SCID-primary account's immutable primary is `{scid}@{domain}`; its
human-chosen alias is whatever its bound DID's *current* did:webvh identifier
names (biset's PLANSCID.md). `GET`/`POST /account/alias`
(`server.rs::account_alias`) is the eager path — a rename adds the new
address and removes the old one immediately — and it is explicitly
best-effort on the remove side (biset's `edit-identity.ts`, `.catch(() =>
false)`), so a crashed client or a lost race can leave a stale alias behind
with nothing to clean it up.

`did/alias_reconcile.rs` is the backstop, on the same cadence as §5's inactive
sweep: for every SCID-primary account it asks the anchor
(`jmapserver::anchor::current_alias`, §2.7) what the bound DID currently
claims, and reconciles the local alias set to match exactly — one address if
the DID's current location is on this relay's own domain, none otherwise
(deactivated, or moved to a domain this relay doesn't serve). A `NotBound` or
`Unknown` answer changes nothing that cycle — an anchor outage must never look
like every renamed identity abandoning its address at once.

The anchor side of this is `ClaimStore.rebind` (biset's
`src/anchor/store.ts`, not this repo): the DID string the anchor recorded at
bind time is never updated by an ordinary rename, so — without rebinding it
to the identity's current location on every successful resolve — a stale
pointer whose OWN original location later falls to the anchor's did:webvh
sweep (a separate TTL, on the *location*, not the alias) would make the
identity unresolvable and `current_alias` would misreport a live account as
gone.

### 2.7 The anchor client

`crates/jmapserver/src/did/anchor.rs` is the whole DID-cryptography boundary: this
relay forwards proofs, it does not check them, so that logic lives in ONE
place rather than being upgraded in lockstep across every relay that might
run it.

| Function | Asks the anchor to… |
|---|---|
| `claim` | record which DID owns `localpart@domain` (§2.3, §2.4) |
| `verify_binding` | verify a proof WITHOUT recording a claim — `authorized_did_domain`'s counterpart to `claim`, since that mode's own non-duplication guarantee makes a registry entry redundant |
| `vouch_device` | check whether a DID's *current* root key authorises a device (§2.2) |
| `release`/`release_ok` | forget a claim, so the name can be provisioned again |
| `current_alias` | what a bound DID currently claims as its address (§2.6) |
| `drain` | release every name at once, for turning a relay anchorless without stranding them |

`Verdict` (`Ok`/`Conflict`/`Invalid`/`Error`) and `AliasLookup`
(`NotBound`/`Unknown`/`Resolved`) both exist to keep two outcomes apart that
callers must never confuse: the anchor *looking and saying no* versus the
anchor being *unreachable*. Every call here is best-effort in one direction
and fatal in the other — an unreachable anchor must never block deleting an
account (the user asked to leave), but it **must** block creating one (an
unbound name can be claimed by somebody else later, and the collision
surfaces as the original owner losing their address).

### 2.8 Route guards for this surface

`routes.rs`'s `Guard` enum is one of four values for every route in the
table, this surface's routes among them:

| Route | Guard | Why |
|---|---|---|
| `POST /account/provision` | `SelfAuth` | the vouch signature is the credential (§2.3) |
| `GET /account/session/challenge` | `Open` | a nonce authorises nothing by itself (§2.2) |
| `POST /account/session` | `SelfAuth` | the device signature is the credential (§2.2) |
| `POST`/`GET`/`DELETE /account/devices` | `SelfAuth` (POST) / `Account` (GET, DELETE) | cold recovery needs POST uncredentialed; GET/DELETE act on an existing account (§2.2) |
| `POST /account/did` | `Account` (anchor build only) | the target comes from Basic Auth, `did_sig` is checked separately (§2.4) |
| `GET`/`POST /account/alias` | `Account` | scoped to the authenticated account only — the target primary never comes from the body (§2.6) |
| `POST /account/migrate-to-scid` | `Account` | a one-time move onto SCID-primary, never an ordinary rename (that's `/account/alias`) |
| `POST /account/delete` | `Account` | routing (the alias table) is dropped before the account's data, so a partial failure never leaves aliases pointing at data that's gone |

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

An account exists **iff** it has an `auth_token_hash` (§2.5) — never by
`envelope.json`, which a third-party or DID-only account does not have. The
startup sweep and the recovery scan use the same rule; if they disagreed, one
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

- **`just difftest`** — the oracle and this port, same scenario, 49 steps,
  compared byte for byte including headers.
- **Interop suites** — per module, driving the oracle's real endpoints or Go
  helper programs linked against the real packages.
- **`just difftest --self-test`** — the harness proving it can fail, by
  mutating the oracle.
- **`just difftest-noanchor`** — the same 49 steps against the *anchorless*
  pair: `go build -tags noanchor` versus `cargo build --no-default-features`.
  A whole build configuration that had never been compared. Since did:dht went
  it means a relay with no DID features at all rather than one that can still
  serve self-certifying identities.
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

- **A DHT node, or any did:dht support.** `/pkarr/` forwarded a client's
  `did:dht` record to the anchor's node; every relay used to run its own node,
  with its own UDP socket, routing table and republish loop. Both are gone with
  the method (SPEC.md §11.27). `routes::tests` fails if the route comes back —
  an open route that proxies a client's bytes to another host is not something
  to reintroduce by accident.
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
