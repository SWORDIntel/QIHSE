//! Bounded, authenticated browser read slice. This file is deliberately not
//! exported until the crate's public API can be updated with its HTTP/WebAuthn
//! integration. No mutation is exposed: `prepare_action` only validates and
//! renders the exact command that a future verified ceremony must bind.

use crate::controller::{ControllerClient, ControllerConfig, ControllerError, Credentials, Reply};
use std::collections::BTreeMap;

pub const MAX_KEYS_PER_NODE: usize = 5000;
pub const PREVIEW_BYTES: usize = 4096;

#[derive(Debug)]
pub enum BrowserError {
    BadArg(&'static str),
    UnknownAction,
    Server { class: String, message: String },
    Controller(ControllerError),
    WrongReply(&'static str),
    UnseededOwner,
}

impl std::fmt::Display for BrowserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadArg(message) | Self::WrongReply(message) => f.write_str(message),
            Self::UnknownAction => f.write_str("action is not in the allowlist"),
            Self::Server { class, message } => write!(f, "{class}: {message}"),
            Self::Controller(error) => write!(f, "{error}"),
            Self::UnseededOwner => f.write_str("slot owner is not a seeded node"),
        }
    }
}

impl std::error::Error for BrowserError {}

impl From<ControllerError> for BrowserError {
    fn from(error: ControllerError) -> Self {
        match error {
            ControllerError::Server { class, message } => Self::Server { class, message },
            other => Self::Controller(other),
        }
    }
}

impl BrowserError {
    fn authoritative(&self) -> bool {
        matches!(self, Self::Server { class, .. } if class == "NOPERM" || class == "NOAUTH")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeSpec {
    pub host: String,
    pub port: u16,
}

impl NodeSpec {
    pub fn parse(text: &str) -> Result<Self, BrowserError> {
        let (host, port) = text.rsplit_once(':').ok_or(BrowserError::BadArg("expected host:port"))?;
        if host.is_empty() || !host.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)) {
            return Err(BrowserError::BadArg("invalid seeded host"));
        }
        let port = port.parse().map_err(|_| BrowserError::BadArg("invalid port"))?;
        if port == 0 { return Err(BrowserError::BadArg("invalid port")); }
        Ok(Self { host: host.to_owned(), port })
    }

    pub fn addr(&self) -> String { format!("{}:{}", self.host, self.port) }
}

/// Every call uses the principal bound to this backend. A backend MUST NOT
/// substitute an unauthenticated connection or a different user's session.
pub trait AuthenticatedFleet {
    fn seeds(&self) -> &[NodeSpec];
    fn call(&mut self, node: usize, args: &[&[u8]]) -> Result<Reply, BrowserError>;
}

/// Real RESP implementation: lazy AUTH on each explicitly seeded node,
/// never on topology-supplied addresses. No default/ambient credential path.
pub struct SessionFleet {
    seeds: Vec<NodeSpec>,
    username: String,
    password: String,
    clients: Vec<Option<ControllerClient>>,
}

impl SessionFleet {
    pub fn new(seeds: Vec<NodeSpec>, username: String, password: String) -> Result<Self, BrowserError> {
        if seeds.is_empty() || username.is_empty() || password.is_empty()
            || username.contains('\0') || password.contains('\0') {
            return Err(BrowserError::BadArg("seeds and explicit credentials required"));
        }
        for seed in &seeds {
            if NodeSpec::parse(&seed.addr())? != *seed {
                return Err(BrowserError::BadArg("invalid seed"));
            }
        }
        let clients = (0..seeds.len()).map(|_| None).collect();
        Ok(Self { seeds, username, password, clients })
    }
}

impl AuthenticatedFleet for SessionFleet {
    fn seeds(&self) -> &[NodeSpec] { &self.seeds }

    fn call(&mut self, node: usize, args: &[&[u8]]) -> Result<Reply, BrowserError> {
        let seed = self.seeds.get(node).ok_or(BrowserError::BadArg("node is not seeded"))?;
        if self.clients[node].is_none() {
            let config = ControllerConfig::new(&seed.host, seed.port, Credentials::Password {
                username: self.username.clone(), password: self.password.clone(),
            });
            self.clients[node] = Some(ControllerClient::connect(&config)?);
        }
        let client = self.clients[node].as_mut().expect("connected above");
        let result = client.call(args).map_err(BrowserError::from);
        if !client.is_connected() { self.clients[node] = None; }
        result
    }
}

fn call_any<F: AuthenticatedFleet>(fleet: &mut F, args: &[&[u8]]) -> Result<Reply, BrowserError> {
    let mut last = None;
    for node in 0..fleet.seeds().len() {
        match fleet.call(node, args) {
            Ok(reply) => return Ok(reply),
            Err(error) if error.authoritative() => return Err(error),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or(BrowserError::BadArg("no seeded node")))
}

pub fn crc16(input: &[u8]) -> u16 {
    let mut crc = 0u16;
    for byte in input {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

pub fn hash_tag(key: &[u8]) -> &[u8] {
    if let Some(start) = key.iter().position(|b| *b == b'{') {
        if let Some(end) = key[start + 1..].iter().position(|b| *b == b'}') {
            if end != 0 { return &key[start + 1..start + 1 + end]; }
        }
    }
    key
}

pub fn keyslot(key: &[u8]) -> u16 { crc16(hash_tag(key)) % 16384 }

fn text(reply: Reply) -> Result<String, BrowserError> {
    match reply {
        Reply::Simple(s) => Ok(s),
        Reply::Bulk(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        _ => Err(BrowserError::WrongReply("expected text")),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyEntry { pub key: String, pub node: usize }

#[derive(Debug)]
pub struct KeyListing {
    pub keys: Vec<KeyEntry>,
    pub truncated: bool,
    pub node_errors: Vec<(usize, BrowserError)>,
}

/// Enumerate only keys returned by the authenticated server. No local
/// classification/tenant inference, and a NOPERM is never converted to [].
pub fn browse<F: AuthenticatedFleet>(fleet: &mut F, pattern: &str, node: Option<usize>, limit: usize) -> Result<KeyListing, BrowserError> {
    if pattern.len() > 256 || limit == 0 || limit > MAX_KEYS_PER_NODE {
        return Err(BrowserError::BadArg("pattern or limit out of range"));
    }
    if let Some(node) = node {
        if node >= fleet.seeds().len() { return Err(BrowserError::BadArg("node is not seeded")); }
    }
    let mut listing = KeyListing { keys: Vec::new(), truncated: false, node_errors: Vec::new() };
    for idx in 0..fleet.seeds().len() {
        if node.is_some() && node != Some(idx) { continue; }
        let reply = match fleet.call(idx, &[b"KEYS", pattern.as_bytes()]) {
            Ok(reply) => reply,
            Err(error) if error.authoritative() => return Err(error),
            Err(error) => { listing.node_errors.push((idx, error)); continue; }
        };
        let Reply::Array(items) = reply else { return Err(BrowserError::WrongReply("KEYS array")); };
        listing.truncated |= items.len() > limit;
        for item in items.into_iter().take(limit) {
            listing.keys.push(KeyEntry { key: text(item)?, node: idx });
        }
    }
    listing.keys.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(listing)
}

fn owner<F: AuthenticatedFleet>(fleet: &mut F, key: &str) -> Result<usize, BrowserError> {
    let slots = call_any(fleet, &[b"CLUSTER", b"SLOTS"])?;
    let Reply::Array(runs) = slots else { return Err(BrowserError::WrongReply("CLUSTER SLOTS array")); };
    for run in runs {
        let Reply::Array(parts) = run else { return Err(BrowserError::WrongReply("slot range")); };
        if parts.len() < 3 { return Err(BrowserError::WrongReply("slot range")); }
        let (Reply::Int(start), Reply::Int(end), Reply::Array(address)) = (&parts[0], &parts[1], &parts[2]) else {
            return Err(BrowserError::WrongReply("slot owner"));
        };
        if *start <= i64::from(keyslot(key.as_bytes())) && i64::from(keyslot(key.as_bytes())) <= *end {
            let (Some(host), Some(Reply::Int(port))) = (address.first().and_then(Reply::as_str), address.get(1)) else {
                return Err(BrowserError::WrongReply("slot owner address"));
            };
            return fleet.seeds().iter().position(|seed| seed.host.eq_ignore_ascii_case(host) && i64::from(seed.port) == *port)
                .ok_or(BrowserError::UnseededOwner);
        }
    }
    Err(BrowserError::UnseededOwner)
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyDetail {
    pub key: String,
    pub node: usize,
    pub exists: bool,
    pub kind: String,
    pub ttl: Option<i64>,
    pub size: Option<i64>,
    pub preview: Option<String>,
    pub truncated: bool,
}

/// Direct-ID lookup: each TYPE/TTL/GETRANGE is server-authorized for the
/// same principal. A denial is an error, not a missing key or empty preview.
pub fn fetch<F: AuthenticatedFleet>(fleet: &mut F, key: &str) -> Result<KeyDetail, BrowserError> {
    if key.is_empty() || key.len() > 512 { return Err(BrowserError::BadArg("name required (<= 512 bytes)")); }
    let node = owner(fleet, key)?;
    let kind = text(fleet.call(node, &[b"TYPE", key.as_bytes()])?)?;
    let mut detail = KeyDetail { key: key.into(), node, exists: kind != "none", kind, ttl: None, size: None, preview: None, truncated: false };
    if !detail.exists { return Ok(detail); }
    let Reply::Int(ttl) = fleet.call(node, &[b"TTL", key.as_bytes()])? else { return Err(BrowserError::WrongReply("TTL integer")); };
    detail.ttl = Some(ttl);
    let size_cmd: Option<&[u8]> = match detail.kind.as_str() {
        "string" => Some(b"STRLEN"), "list" => Some(b"LLEN"), "hash" => Some(b"HLEN"),
        "set" => Some(b"SCARD"), "zset" => Some(b"ZCARD"), _ => None,
    };
    if let Some(cmd) = size_cmd {
        let Reply::Int(size) = fleet.call(node, &[cmd, key.as_bytes()])? else { return Err(BrowserError::WrongReply("size integer")); };
        detail.size = Some(size);
    }
    if detail.kind == "string" {
        let Reply::Bulk(bytes) = fleet.call(node, &[b"GETRANGE", key.as_bytes(), b"0", b"4095"])? else {
            return Err(BrowserError::WrongReply("GETRANGE bulk"));
        };
        if bytes.len() > PREVIEW_BYTES { return Err(BrowserError::WrongReply("unbounded preview")); }
        detail.truncated = bytes.len() == PREVIEW_BYTES;
        detail.preview = Some(String::from_utf8_lossy(&bytes).into_owned());
    }
    Ok(detail)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg { Int(i64), Text(String), Bool(bool) }
pub type ActionArgs = BTreeMap<String, Arg>;

fn int_arg(args: &ActionArgs, name: &str, lo: i64, hi: i64) -> Result<i64, BrowserError> {
    match args.get(name) {
        Some(Arg::Int(n)) if (lo..=hi).contains(n) => Ok(*n),
        _ => Err(BrowserError::BadArg("invalid integer argument")),
    }
}
fn str_arg(args: &ActionArgs, name: &str, max: usize) -> Result<String, BrowserError> {
    match args.get(name) {
        Some(Arg::Text(s)) if !s.is_empty() && s.chars().count() <= max => Ok(s.clone()),
        _ => Err(BrowserError::BadArg("invalid string argument")),
    }
}
fn enum_arg(args: &ActionArgs, name: &str, allowed: &[&str]) -> Result<String, BrowserError> {
    let value = str_arg(args, name, 32)?.to_ascii_uppercase();
    if allowed.contains(&value.as_str()) { Ok(value) } else { Err(BrowserError::BadArg("invalid enum argument")) }
}
fn uuid(args: &ActionArgs) -> Result<String, BrowserError> {
    let value = str_arg(args, "uuid", 32)?;
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BrowserError::BadArg("invalid uuid"));
    }
    Ok(value.to_ascii_lowercase())
}

#[derive(Debug, PartialEq, Eq)]
pub struct PreparedAction { pub canonical: String, pub wire: Vec<String> }

/// Prepare only; this does not confer permission to dispatch. The dispatch
/// token and UV assertion must be verified by a full WebAuthn/HTTP port first.
pub fn prepare_action(seeds: &[NodeSpec], name: &str, args: &ActionArgs) -> Result<PreparedAction, BrowserError> {
    let wire: Vec<String> = match name {
        "moveslots" => {
            let first = int_arg(args, "first", 0, 16383)?;
            let last = int_arg(args, "last", 0, 16383)?;
            if first > last { return Err(BrowserError::BadArg("first must be <= last")); }
            let target = str_arg(args, "target", 258)?;
            let target_spec = NodeSpec::parse(&target)?;
            if !seeds.iter().any(|seed| seed.host.eq_ignore_ascii_case(&target_spec.host) && seed.port == target_spec.port) {
                return Err(BrowserError::BadArg("target is not seeded"));
            }
            vec!["CLUSTER".into(), "MOVESLOTS".into(), format!("{first}-{last}"), target]
        }
        "trust_set" => vec!["FEDERATION".into(), "TRUST.SET".into(), uuid(args)?,
            enum_arg(args, "state", &["PENDING", "APPROVED", "REVOKED"])?, str_arg(args, "result", 64)?],
        "node_approve" | "node_revoke" => vec!["FEDERATION".into(),
            if name == "node_approve" { "NODE.APPROVE" } else { "NODE.REVOKE" }.into(), uuid(args)?],
        "lease_release" | "lease_renew" => vec!["FEDERATION".into(),
            if name == "lease_release" { "LEASE.RELEASE" } else { "LEASE.RENEW" }.into(), str_arg(args, "lease_id", 256)?],
        "fed_state" => vec!["FEDERATION".into(), "STATE".into(),
            enum_arg(args, "state", &["CONNECTED", "DEGRADED", "ISOLATED", "RECOVERING", "FENCED", "MAINTENANCE"]) ?],
        "ns_register" => vec!["FEDERATION".into(), "NS.REGISTER".into(), str_arg(args, "name", 128)?,
            enum_arg(args, "class", &["LOCAL", "EVENTUAL", "CAUSAL", "QUORUM", "LINEARIZABLE"]) ?],
        "ns_unregister" => vec!["FEDERATION".into(), "NS.UNREGISTER".into(), str_arg(args, "name", 128)?],
        "bgsave" => vec!["BGSAVE".into()],
        _ => return Err(BrowserError::UnknownAction),
    };
    if wire.iter().any(|arg| arg.contains(['\r', '\n', '\0'])) { return Err(BrowserError::BadArg("unsafe command argument")); }
    let canonical = wire.join(" ");
    Ok(PreparedAction { canonical, wire })
}
