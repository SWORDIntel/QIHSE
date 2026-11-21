//! Browser slice tests: scripted authenticated RESP replies, no sockets or
//! network side effects. The C/Python negative test owns the real engine's
//! clearance/SCI enforcement; these tests pin adapter propagation.
pub use qihse_rs::controller;
#[path = "../src/python_browser.rs"]
mod python_browser;

use controller::Reply;
use python_browser::{browse, fetch, keyslot, prepare_action, ActionArgs, Arg, AuthenticatedFleet,
                     BrowserError, NodeSpec};
use std::collections::VecDeque;

struct Step { node: usize, args: Vec<Vec<u8>>, reply: Result<Reply, BrowserError> }
struct Script { seeds: Vec<NodeSpec>, steps: VecDeque<Step> }

impl Script {
    fn new(seeds: &[&str], steps: Vec<Step>) -> Self {
        Self { seeds: seeds.iter().map(|s| NodeSpec::parse(s).unwrap()).collect(), steps: steps.into() }
    }
    fn finished(&self) { assert!(self.steps.is_empty(), "missing commands"); }
}
impl AuthenticatedFleet for Script {
    fn seeds(&self) -> &[NodeSpec] { &self.seeds }
    fn call(&mut self, node: usize, args: &[&[u8]]) -> Result<Reply, BrowserError> {
        let step = self.steps.pop_front().expect("unexpected network command");
        assert_eq!(node, step.node);
        assert_eq!(args, step.args.iter().map(Vec::as_slice).collect::<Vec<_>>());
        step.reply
    }
}
fn step(node: usize, args: &[&[u8]], reply: Result<Reply, BrowserError>) -> Step {
    Step { node, args: args.iter().map(|v| v.to_vec()).collect(), reply }
}
fn denied(class: &str) -> BrowserError {
    BrowserError::Server { class: class.into(), message: "classified or wrong tenant".into() }
}
fn slots(host: &str, port: i64) -> Reply {
    Reply::Array(vec![Reply::Array(vec![Reply::Int(0), Reply::Int(16383),
        Reply::Array(vec![Reply::Bulk(host.as_bytes().to_vec()), Reply::Int(port)])])])
}

#[test]
fn slot_vectors_and_hash_tags_match_python() {
    assert_eq!(python_browser::crc16(b"123456789"), 0x31c3);
    assert_eq!(keyslot(b"foo"), 12182);
    assert_eq!(keyslot(b"bar"), 5061);
    assert_eq!(keyslot(b"hello"), 866);
    assert_eq!(keyslot(b"{user}.following"), keyslot(b"user"));
    assert_eq!(keyslot(b"{}foo"), python_browser::crc16(b"{}foo") % 16384);
}

#[test]
fn classified_and_sci_filtered_keys_never_materialize() {
    // The real server's authenticated KEYS reply excludes high-classification
    // and unheld-SCI records. No client-side fallback or raw read is used.
    let mut fleet = Script::new(&["n0:7100"], vec![step(0, &[b"KEYS", b"*"],
        Ok(Reply::Array(vec![Reply::Bulk(b"pub:welcome".to_vec())])))]);
    let listing = browse(&mut fleet, "*", None, 50).unwrap();
    assert_eq!(listing.keys.len(), 1);
    assert_eq!(listing.keys[0].key, "pub:welcome");
    assert!(!format!("{listing:?}").contains("sec:codeword-roster"));
    fleet.finished();
}

#[test]
fn low_clearance_and_tenant_denials_are_not_successful_empty_listings() {
    for class in ["NOPERM", "NOAUTH"] {
        let mut fleet = Script::new(&["n0:7100", "n1:7101"], vec![
            step(0, &[b"KEYS", b"*"], Err(denied(class))),
        ]);
        assert!(matches!(browse(&mut fleet, "*", None, 50), Err(BrowserError::Server { class: c, .. }) if c == class));
        fleet.finished(); // no second-node failover on authoritative refusal
    }
}

#[test]
fn direct_id_denial_never_fetches_value_or_metadata() {
    let mut fleet = Script::new(&["n0:7100"], vec![
        step(0, &[b"CLUSTER", b"SLOTS"], Ok(slots("n0", 7100))),
        step(0, &[b"TYPE", b"sec:natsec-brief"], Err(denied("NOPERM"))),
    ]);
    assert!(matches!(fetch(&mut fleet, "sec:natsec-brief"), Err(BrowserError::Server { class, .. }) if class == "NOPERM"));
    fleet.finished(); // no GETRANGE after refusal
}

#[test]
fn invisible_record_is_indistinguishable_from_missing_and_no_value_read() {
    // Engine can deliberately return TYPE none instead of NOPERM for an
    // under-cleared key; preserve that server contract without probing further.
    let mut fleet = Script::new(&["n0:7100"], vec![
        step(0, &[b"CLUSTER", b"SLOTS"], Ok(slots("n0", 7100))),
        step(0, &[b"TYPE", b"sec:natsec-brief"], Ok(Reply::Simple("none".into()))),
    ]);
    let detail = fetch(&mut fleet, "sec:natsec-brief").unwrap();
    assert!(!detail.exists);
    assert!(detail.preview.is_none());
    assert!(detail.ttl.is_none());
    fleet.finished();
}

#[test]
fn seeded_owner_only_and_bounded_string_preview() {
    let mut fleet = Script::new(&["n0:7100", "n1:7101"], vec![
        step(0, &[b"CLUSTER", b"SLOTS"], Ok(slots("N1", 7101))),
        step(1, &[b"TYPE", b"pub:welcome"], Ok(Reply::Simple("string".into()))),
        step(1, &[b"TTL", b"pub:welcome"], Ok(Reply::Int(-1))),
        step(1, &[b"STRLEN", b"pub:welcome"], Ok(Reply::Int(5))),
        step(1, &[b"GETRANGE", b"pub:welcome", b"0", b"4095"], Ok(Reply::Bulk(b"hello".to_vec()))),
    ]);
    let detail = fetch(&mut fleet, "pub:welcome").unwrap();
    assert_eq!((detail.node, detail.preview.as_deref(), detail.size), (1, Some("hello"), Some(5)));
    fleet.finished();

    let mut fleet = Script::new(&["n0:7100"], vec![step(0, &[b"CLUSTER", b"SLOTS"],
        Ok(slots("attacker.example", 7390)))]);
    assert!(matches!(fetch(&mut fleet, "pub:welcome"), Err(BrowserError::UnseededOwner)));
    fleet.finished(); // never connect to an address advertised by the server
}

#[test]
fn listing_bounds_and_failed_nodes_are_explicit() {
    let mut fleet = Script::new(&["n0:7100", "n1:7101"], vec![
        step(0, &[b"KEYS", b"pub:*"], Err(BrowserError::BadArg("transport unavailable"))),
        step(1, &[b"KEYS", b"pub:*"], Ok(Reply::Array(vec![Reply::Bulk(b"pub:b".to_vec()), Reply::Bulk(b"pub:a".to_vec())]))),
    ]);
    let listing = browse(&mut fleet, "pub:*", None, 1).unwrap();
    assert_eq!(listing.keys.len(), 1);
    assert!(listing.truncated);
    assert_eq!(listing.node_errors.len(), 1);
    fleet.finished();
    assert!(matches!(browse(&mut fleet, &"*".repeat(257), None, 1), Err(BrowserError::BadArg(_))));
    assert!(matches!(browse(&mut fleet, "*", Some(99), 1), Err(BrowserError::BadArg(_))));
}

#[test]
fn explicit_principal_required_before_any_network_call() {
    use python_browser::SessionFleet;
    let seed = NodeSpec::parse("n0:7100").unwrap();
    assert!(SessionFleet::new(vec![], "u".into(), "p".into()).is_err());
    assert!(SessionFleet::new(vec![seed.clone()], "".into(), "p".into()).is_err());
    assert!(SessionFleet::new(vec![seed.clone()], "low".into(), "".into()).is_err());
    assert!(SessionFleet::new(vec![seed.clone()], "low\0op".into(), "p".into()).is_err());
    assert!(SessionFleet::new(vec![seed], "low".into(), "p".into()).is_ok());
}

#[test]
fn denied_preview_does_not_return_partial_metadata_as_success() {
    let mut fleet = Script::new(&["n0:7100"], vec![
        step(0, &[b"CLUSTER", b"SLOTS"], Ok(slots("n0", 7100))),
        step(0, &[b"TYPE", b"sec:codeword-roster"], Ok(Reply::Simple("string".into()))),
        step(0, &[b"TTL", b"sec:codeword-roster"], Ok(Reply::Int(-1))),
        step(0, &[b"STRLEN", b"sec:codeword-roster"], Ok(Reply::Int(21))),
        step(0, &[b"GETRANGE", b"sec:codeword-roster", b"0", b"4095"], Err(denied("NOPERM"))),
    ]);
    let err = fetch(&mut fleet, "sec:codeword-roster").unwrap_err();
    assert!(matches!(err, BrowserError::Server { class, .. } if class == "NOPERM"));
    fleet.finished();
}

fn arg_pairs(pairs: &[(&str, Arg)]) -> ActionArgs {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

#[test]
fn prepared_actions_are_exact_and_never_dispatched() {
    let seeds = [NodeSpec::parse("n0:7100").unwrap(), NodeSpec::parse("10.0.0.5:7101").unwrap()];
    let args = arg_pairs(&[("first", Arg::Int(0)), ("last", Arg::Int(100)),
        ("target", Arg::Text("10.0.0.5:7101".into()))]);
    let prepared = prepare_action(&seeds, "moveslots", &args).unwrap();
    assert_eq!(prepared.canonical, "CLUSTER MOVESLOTS 0-100 10.0.0.5:7101");
    assert_eq!(prepared.wire, ["CLUSTER", "MOVESLOTS", "0-100", "10.0.0.5:7101"]);
    let mut bad = args.clone();
    bad.insert("target".into(), Arg::Text("evil.example:7101".into()));
    assert!(matches!(prepare_action(&seeds, "moveslots", &bad), Err(BrowserError::BadArg(_))));
    bad.insert("target".into(), Arg::Text("n0:7100".into()));
    bad.insert("last".into(), Arg::Int(-1));
    assert!(matches!(prepare_action(&seeds, "moveslots", &bad), Err(BrowserError::BadArg(_))));
    bad.insert("last".into(), Arg::Bool(true));
    assert!(matches!(prepare_action(&seeds, "moveslots", &bad), Err(BrowserError::BadArg(_))));
    assert!(matches!(prepare_action(&seeds, "shutdown", &ActionArgs::new()), Err(BrowserError::UnknownAction)));
    let trust = arg_pairs(&[("uuid", Arg::Text("AB".repeat(16))),
        ("state", Arg::Text("approved".into())), ("result", Arg::Text("attested".into()))]);
    assert_eq!(prepare_action(&seeds, "trust_set", &trust).unwrap().canonical,
        format!("FEDERATION TRUST.SET {} APPROVED attested", "ab".repeat(16)));
    let mut injected = trust;
    injected.insert("result".into(), Arg::Text("ok\nSHUTDOWN".into()));
    assert!(matches!(prepare_action(&seeds, "trust_set", &injected), Err(BrowserError::BadArg(_))));
}
