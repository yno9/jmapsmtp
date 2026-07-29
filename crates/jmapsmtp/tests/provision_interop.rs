//! `POST /account/provision`, compared against the oracle request by request.
//!
//! This endpoint is where a DID becomes an account, so every refusal is part
//! of the contract with biset's client — it branches on them. Driving the real
//! binary is the only way to know the port agrees: the decision depends on the
//! build (anchor or not), the config, the DID's method, and what is already on
//! disk, and no reading of the source covers that cross product.
//!
//! The oracle here is **anchorless**. That is the interesting configuration,
//! not the degenerate one: it is where `did:dht` and `did:webvh` diverge,
//! because a did:dht identifier carries its own root key while a did:webvh
//! SCID is a hash of the identity's genesis log entry and needs resolving
//! (SPEC.md §10-A). An anchored oracle would try to reach a real anchor.

use ed25519_dalek::{Signer as _, SigningKey};
use jmapserver::diddht;
use jmapsmtp::config::{Config, DynamicDomains};
use jmapsmtp::provision::{
    ProvisionRequest, Refusal, VouchPath, may_provision, resolve_domain, validate, vouch_path,
};

mod oracle_harness;
use oracle_harness::Oracle;

/// One open domain, one gated, one privileged — the three provisioning
/// policies — and no anchor.
fn config_json(http_port: u16, smtp_port: u16) -> String {
    format!(
        r#"{{"listen_addr":"127.0.0.1:{http_port}","smtp_port":{smtp_port},
            "base_url":"http://127.0.0.1:{http_port}","hostname":"t.invalid",
            "domain":{{
              "open.test":{{"allow_provision":true}},
              "gated.test":{{"provision_secret":"s3cret"}},
              "closed.test":{{}}
            }}}}"#
    )
}

fn rust_config() -> Config {
    serde_json::from_str(&config_json(1, 1)).unwrap()
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A did:dht identity, its device, and a genuine vouch. The identifier *is*
/// the root public key, so this verifies with no anchor involved.
struct Identity {
    did: String,
    device_pub_key: String,
    vouch_sig: String,
    ts: i64,
}

fn did_dht_identity(seed: u8, label: &str) -> Identity {
    let root = SigningKey::from_bytes(&[seed; 32]);
    let did = format!(
        "did:dht:{}",
        diddht::zbase32_encode(&root.verifying_key().to_bytes())
    );
    let device = SigningKey::from_bytes(&[seed.wrapping_add(1); 32]);
    let device_pub_key = b64url(&device.verifying_key().to_bytes());
    let ts = now();
    let vouch_sig = b64(&root
        .sign(diddht::vouch_statement(&did, &device_pub_key, label, ts).as_bytes())
        .to_bytes());
    Identity {
        did,
        device_pub_key,
        vouch_sig,
        ts,
    }
}

/// A webvh DID in biset's canonical shape. Nothing here can verify a vouch for
/// it — the SCID is a hash, not a key.
const DID_WEBVH: &str =
    "did:webvh:QmSCIDPlaceholder1111111111111111111111111111:biset.md:dids:alice";

fn body(req: &ProvisionRequest) -> String {
    serde_json::json!({
        "username": req.username,
        "domain": req.domain,
        "did": req.did,
        "did_sig": req.did_sig,
        "bind_ts": req.bind_ts,
        "device_pub_key": req.device_pub_key,
        "device_label": req.device_label,
        "device_vouch_ts": req.device_vouch_ts,
        "device_vouch_sig": req.device_vouch_sig,
        "provision_secret": req.provision_secret,
    })
    .to_string()
}

fn request(id: &Identity, username: &str, domain: &str) -> ProvisionRequest {
    ProvisionRequest {
        username: username.into(),
        domain: domain.into(),
        did: id.did.clone(),
        did_sig: "c2ln".into(),
        bind_ts: id.ts,
        device_pub_key: id.device_pub_key.clone(),
        device_label: "Laptop".into(),
        device_vouch_ts: id.ts,
        device_vouch_sig: id.vouch_sig.clone(),
        ..Default::default()
    }
}

/// This port's verdict, as a status code, for the checks that need no network.
///
/// Deliberately does not reimplement the handler — it runs the same decision
/// functions the handler will, in the same order, which is what the comparison
/// is about.
fn our_status(cfg: &Config, req: &ProvisionRequest) -> u16 {
    if let Err(r) = validate(cfg, req) {
        return r.status();
    }
    let (_, dom_cfg) = match resolve_domain(cfg, &DynamicDomains::default(), &req.domain) {
        Ok(v) => v,
        Err(r) => return r.status(),
    };
    if let Err(r) = may_provision(&dom_cfg, &req.provision_secret) {
        return r.status();
    }
    match vouch_path(cfg, &req.did) {
        VouchPath::Impossible => Refusal::DidMethodNeedsAnchor.status(),
        // A real vouch, verified locally, so this is a success. The signature
        // itself is checked by devicekeys_interop.
        VouchPath::Local => 201,
        VouchPath::Anchor => unreachable!("this oracle is anchorless"),
    }
}

/// Every refusal, and the one success, compared to the oracle.
#[test]
fn this_port_refuses_exactly_what_the_oracle_refuses() {
    let Some(o) = Oracle::start_with("PROVISION_INTEROP", config_json, |_| {}) else {
        return;
    };
    let cfg = rust_config();

    // Each case gets its own identity and username, so an account created by
    // an earlier case cannot change a later one's answer.
    let mut cases: Vec<(&str, ProvisionRequest)> = Vec::new();

    let id = did_dht_identity(9, "Laptop");
    cases.push((
        "a did:dht identity on the open domain",
        request(&id, "alice", "open.test"),
    ));

    let id2 = did_dht_identity(21, "Laptop");
    let mut r = request(&id2, "bob", "");
    r.domain = String::new();
    cases.push(("no domain, so the open one", r));

    let id3 = did_dht_identity(31, "Laptop");
    cases.push(("a bad username", request(&id3, "Bad Name", "open.test")));

    let id4 = did_dht_identity(41, "Laptop");
    cases.push((
        "a username that is a path",
        request(&id4, "../etc", "open.test"),
    ));

    // Case is the one thing that is normalised rather than refused, so this
    // succeeds and lands on `nora`. Both implementations fold before checking.
    let id4b = did_dht_identity(141, "Laptop");
    cases.push((
        "an uppercase username, which is folded",
        request(&id4b, "  Nora  ", "open.test"),
    ));

    let id5 = did_dht_identity(51, "Laptop");
    let mut r = request(&id5, "carol", "open.test");
    r.did = String::new();
    cases.push(("no did", r));

    let id6 = did_dht_identity(61, "Laptop");
    let mut r = request(&id6, "dave", "open.test");
    r.device_pub_key = String::new();
    cases.push(("no device_pub_key", r));

    let id7 = did_dht_identity(71, "Laptop");
    let mut r = request(&id7, "erin", "open.test");
    r.device_vouch_sig = String::new();
    cases.push(("no device_vouch_sig", r));

    let id8 = did_dht_identity(81, "Laptop");
    cases.push(("an unknown domain", request(&id8, "frank", "nope.test")));

    let id9 = did_dht_identity(91, "Laptop");
    cases.push((
        "a gated domain with no secret",
        request(&id9, "grace", "gated.test"),
    ));

    let id10 = did_dht_identity(101, "Laptop");
    let mut r = request(&id10, "heidi", "gated.test");
    r.provision_secret = "wrong".into();
    cases.push(("a gated domain with the wrong secret", r));

    let id11 = did_dht_identity(111, "Laptop");
    let mut r = request(&id11, "ivan", "gated.test");
    r.provision_secret = "s3cret".into();
    cases.push(("a gated domain with the right secret", r));

    let id12 = did_dht_identity(121, "Laptop");
    cases.push(("a privileged domain", request(&id12, "judy", "closed.test")));

    // The one this whole module is about: webvh needs the anchor, and there is
    // none.
    let id13 = did_dht_identity(131, "Laptop");
    let mut r = request(&id13, "karl", "open.test");
    r.did = DID_WEBVH.into();
    cases.push(("a did:webvh on an anchorless relay", r));

    for (name, req) in &cases {
        let (status, go_body) = o.post_json("/account/provision", &body(req));
        assert_eq!(
            our_status(&cfg, req),
            status,
            "{name}: the oracle said {status} {go_body:?}"
        );
    }

    // The folded name is the one that got created, not the submitted spelling.
    assert!(
        o.data_dir().join("open.test/nora").is_dir(),
        "the account should be at the folded name"
    );
    assert!(!o.data_dir().join("open.test/  Nora  ").exists());

    // …and the messages, for the cases a client branches on by text.
    let webvh = &cases.last().expect("the webvh case is last").1;
    assert_eq!(webvh.did, DID_WEBVH);
    let (_, go_body) = o.post_json("/account/provision", &body(webvh));
    assert!(
        go_body.contains("identity anchor"),
        "the webvh refusal should name the anchor, not look like a bad vouch: {go_body:?}"
    );
    assert_eq!(
        Refusal::DidMethodNeedsAnchor.message(),
        go_body.trim(),
        "this port sends the same message"
    );
}

/// A name is taken by either credential shape. This flow writes no
/// `auth_token_hash` at all, so a check that only looked at that file would
/// hand an existing account to whoever asked.
#[test]
fn a_second_request_for_the_same_name_conflicts_on_both_implementations() {
    let Some(o) = Oracle::start_with("PROVISION_INTEROP", config_json, |_| {}) else {
        return;
    };

    let first = did_dht_identity(7, "Laptop");
    let req = request(&first, "taken", "open.test");
    let (status, b) = o.post_json("/account/provision", &body(&req));
    assert_eq!(status, 201, "the first request should create it: {b:?}");

    // The account exists with a device key and no auth_token_hash — exactly
    // the shape a hash-only collision check misses.
    let acct = o.data_dir().join("open.test/taken");
    assert!(
        !jmapserver::devicekeys::list_device_keys(&acct).is_empty(),
        "the device key is the credential"
    );
    assert!(
        !acct.join("auth_token_hash").exists(),
        "this flow writes no static credential"
    );

    // A different identity asking for the same name.
    let second = did_dht_identity(77, "Laptop");
    let (status, _) = o.post_json(
        "/account/provision",
        &body(&request(&second, "taken", "open.test")),
    );
    assert_eq!(status, Refusal::UsernameTaken.status());

    assert!(
        jmapsmtp::provision::name_is_taken(&acct, &o.data_dir(), "open.test", "taken", false),
        "this port agrees the name is taken, on the same files"
    );
}

/// `did_bound` appears only when the client sent a DID, and is false here
/// because there is no anchor to bind at.
#[test]
fn the_response_reports_an_unbound_did_on_an_anchorless_relay() {
    let Some(o) = Oracle::start_with("PROVISION_INTEROP", config_json, |_| {}) else {
        return;
    };
    let id = did_dht_identity(13, "Laptop");
    let (status, go_body) = o.post_json(
        "/account/provision",
        &body(&request(&id, "mallory", "open.test")),
    );
    assert_eq!(status, 201, "{go_body}");

    let parsed: serde_json::Value = serde_json::from_str(&go_body).unwrap();
    assert_eq!(parsed["email"], "mallory@open.test");
    assert_eq!(
        parsed["did_bound"], false,
        "a did was sent, and this relay cannot bind it"
    );
    assert!(
        !jmapsmtp::provision::did_bound(&rust_config(), &request(&id, "mallory", "open.test")),
        "this port agrees"
    );
}
