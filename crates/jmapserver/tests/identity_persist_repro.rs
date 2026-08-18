//! Regression coverage for a reported "Identity/set doesn't persist" bug
//! (PLANSCID.md, 2026-08-18): confirms the server-side round trip is
//! correct — a name written via `Identity/set` survives a brand-new
//! `Store::open` on the same directory, simulating a relay restart. The
//! actual bug turned out to be client-side (biset's `store/identities.ts`
//! was a single unscoped list overwritten wholesale by whichever account
//! synced last), but this stays as a guard on the server half of that
//! investigation.
use jmap_types::Id;
use serde_json::json;

#[test]
fn identity_name_survives_a_fresh_store_open() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let acct = Id::from("alice@a.test");

    let store1 = jmapserver::Store::open(dir).unwrap();
    let set_res = store1
        .dispatch(
            &acct,
            "Identity/set",
            &json!({
                "update": { format!("identity-{acct}"): { "name": "Alice A" } }
            }),
            "1970-01-01T00:00:00Z",
        )
        .unwrap();
    println!("SET RESULT: {set_res}");

    let get_res_same = store1
        .dispatch(&acct, "Identity/get", &json!({}), "1970-01-01T00:00:00Z")
        .unwrap();
    println!("GET RESULT (same store): {get_res_same}");

    // Simulate a fresh reload / restart: a NEW Store opened from the SAME dir.
    let store2 = jmapserver::Store::open(dir).unwrap();
    let get_res_fresh = store2
        .dispatch(&acct, "Identity/get", &json!({}), "1970-01-01T00:00:00Z")
        .unwrap();
    println!("GET RESULT (fresh store): {get_res_fresh}");

    let name = get_res_fresh["list"][0]["name"].as_str().unwrap();
    assert_eq!(name, "Alice A", "name lost across a fresh Store::open");
}
