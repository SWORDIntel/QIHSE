//! Authenticated AIMEM remote calls corresponding to the scoped Python SDK.
//!
//! This module uses `controller::ControllerClient` for RESP framing, bounds,
//! deadlines and AUTH; it does not implement another transport. The current
//! controller transport is plaintext TCP, so this adapter accepts only numeric
//! loopback peers. QKP/pinned peers require a sealed transport in the controller
//! before they can be exposed here; never silently downgrade a QKP endpoint.
//! Python remains the active full-featured client. The crate root must opt in
//! to this module separately; the standalone tests include it by path.

use crate::controller::{ControllerClient, ControllerConfig, ControllerError, Credentials, Reply};

/// Explicit hierarchical AIMEM project scope; each token is at most 63 ASCII bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    project: String,
    worktree: String,
    workstream: String,
    session: String,
}

impl Scope {
    pub fn new(project: &str, worktree: &str, workstream: &str, session: &str) -> Result<Self, ControllerError> {
        let fields = [project, worktree, workstream, session];
        if project.is_empty() || (!workstream.is_empty() && worktree.is_empty())
            || (!session.is_empty() && workstream.is_empty())
            || fields.iter().any(|v| v.len() > 63 || !v.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)))
        {
            return Err(ControllerError::InvalidConfig("invalid AIMEM scope"));
        }
        Ok(Self {
            project: project.into(), worktree: worktree.into(),
            workstream: workstream.into(), session: session.into(),
        })
    }

    fn args(&self) -> [&[u8]; 4] {
        [self.project.as_bytes(), self.worktree.as_bytes(),
         self.workstream.as_bytes(), self.session.as_bytes()]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemoryHit {
    pub id: String,
    pub created_ms: u64,
    pub kind: u64,
    pub classification: u64,
    pub sci_compartment: u64,
    pub score: f64,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableReceipt {
    pub operation: String,
    pub id: String,
    pub token: String,
    /// `local-fsync` does not assert replication or quorum durability.
    pub durability: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecallMode { Bm25, Semantic, Hybrid }

impl RecallMode {
    fn wire(self) -> &'static [u8] {
        match self { Self::Bm25 => b"bm25", Self::Semantic => b"semantic", Self::Hybrid => b"hybrid" }
    }
}

fn unexpected(expected: &'static str, got: Reply) -> ControllerError {
    ControllerError::UnexpectedReply { expected, got }
}

fn text(reply: Reply) -> Result<String, ControllerError> {
    match reply {
        Reply::Simple(s) => Ok(s),
        Reply::Bulk(bytes) => String::from_utf8(bytes).map_err(|e| unexpected("UTF-8 text", Reply::Bulk(e.into_bytes()))),
        got => Err(unexpected("UTF-8 text", got)),
    }
}

fn hit(reply: Reply) -> Result<MemoryHit, ControllerError> {
    const SHAPE: &str = "AIMEM hit [id, created_ms, kind, classification, sci, score, text]";
    let Reply::Array(ref fields) = reply else { return Err(unexpected(SHAPE, reply)) };
    if fields.len() != 7 { return Err(unexpected(SHAPE, reply)); }
    let u = |idx: usize| fields[idx].as_str().and_then(|s| s.parse::<u64>().ok());
    let parsed = (|| Some(MemoryHit {
        id: fields[0].as_str()?.to_owned(), created_ms: u(1)?, kind: u(2)?,
        classification: u(3)?, sci_compartment: u(4)?,
        score: fields[5].as_str()?.parse::<f64>().ok().filter(|n| n.is_finite())?,
        text: fields[6].as_str()?.to_owned(),
    }))();
    parsed.ok_or_else(|| unexpected(SHAPE, reply))
}

fn receipt(reply: Reply, expected_op: &str) -> Result<DurableReceipt, ControllerError> {
    const SHAPE: &str = "AIMEM [operation, id, receipt, local-fsync]";
    let Reply::Array(ref fields) = reply else { return Err(unexpected(SHAPE, reply)) };
    if fields.len() != 4 { return Err(unexpected(SHAPE, reply)); }
    let parsed = (|| Some(DurableReceipt {
        operation: fields[0].as_str()?.into(), id: fields[1].as_str()?.into(),
        token: fields[2].as_str()?.into(), durability: fields[3].as_str()?.into(),
    }))();
    match parsed {
        Some(r) if r.operation == expected_op && r.durability == "local-fsync" && !r.id.is_empty() && !r.token.is_empty() => Ok(r),
        _ => Err(unexpected(SHAPE, reply)),
    }
}

/// AIMEM over one authenticated, loopback-only controller connection.
/// No caller can construct this with `Credentials::Unauthenticated`.
pub struct AIMEMClient {
    wire: ControllerClient,
    scope: Scope,
}

impl AIMEMClient {
    pub fn connect(config: &ControllerConfig, scope: Scope) -> Result<Self, ControllerError> {
        if config.host != "127.0.0.1" && config.host != "::1" {
            return Err(ControllerError::InvalidConfig("AIMEM requires numeric loopback until pinned QKP transport is available"));
        }
        match &config.credentials {
            Credentials::Password { username, password }
                if !username.is_empty() && !password.is_empty()
                    && !username.contains('\0') && !password.contains('\0') => {},
            _ => return Err(ControllerError::InvalidConfig("AIMEM requires an explicit authenticated principal")),
        }
        Ok(Self { wire: ControllerClient::connect(config)?, scope })
    }

    fn call(wire: &mut ControllerClient, args: &[&[u8]]) -> Result<Reply, ControllerError> {
        let mut cmd = Vec::with_capacity(args.len() + 1);
        cmd.push(&b"AIMEM"[..]);
        cmd.extend_from_slice(args);
        wire.call(&cmd)
    }

    pub fn store(&mut self, kind: u8, content: &str, key: Option<&str>, durable: bool) -> Result<String, ControllerError> {
        if !(1..=2).contains(&kind) || content.is_empty() || content.len() > 256 * 1024 {
            return Err(ControllerError::InvalidConfig("invalid AIMEM kind or content"));
        }
        let kind = kind.to_string();
        let mut args = vec![if durable { &b"STORE-SCOPED-DURABLE"[..] } else { &b"STORE-SCOPED"[..] }, kind.as_bytes(), content.as_bytes()];
        args.extend(self.scope.args());
        if let Some(key) = key { args.push(key.as_bytes()); }
        text(Self::call(&mut self.wire, &args)?)
    }

    pub fn store_receipt(&mut self, kind: u8, content: &str, key: &str) -> Result<DurableReceipt, ControllerError> {
        if !(1..=2).contains(&kind) || content.is_empty() || content.len() > 256 * 1024 || key.is_empty() {
            return Err(ControllerError::InvalidConfig("invalid AIMEM store receipt parameters"));
        }
        let kind = kind.to_string();
        let mut args = vec![&b"STORE-SCOPED-RECEIPT"[..], kind.as_bytes(), content.as_bytes()];
        args.extend(self.scope.args());
        args.push(key.as_bytes());
        receipt(Self::call(&mut self.wire, &args)?, "STORE-SCOPED")
    }

    pub fn recall(&mut self, query: &str, limit: u8, mode: RecallMode, kind: u8) -> Result<Vec<MemoryHit>, ControllerError> {
        if !(1..=128).contains(&limit) || kind > 2 {
            return Err(ControllerError::InvalidConfig("invalid AIMEM recall parameters"));
        }
        let (limit, kind) = (limit.to_string(), kind.to_string());
        let mut args = vec![&b"RECALL-SCOPED"[..], query.as_bytes(), limit.as_bytes(), mode.wire(), kind.as_bytes()];
        args.extend(self.scope.args());
        match Self::call(&mut self.wire, &args)? {
            Reply::Array(items) => items.into_iter().map(hit).collect(),
            got => Err(unexpected("AIMEM recall array", got)),
        }
    }

    pub fn get(&mut self, id: &str) -> Result<Option<MemoryHit>, ControllerError> {
        let mut args = vec![&b"GET-SCOPED"[..], id.as_bytes()];
        args.extend(self.scope.args());
        match Self::call(&mut self.wire, &args)? { Reply::Nil => Ok(None), r => hit(r).map(Some) }
    }

    pub fn forget(&mut self, id: &str, durable: bool) -> Result<bool, ControllerError> {
        let mut args = vec![if durable { &b"FORGET-SCOPED-DURABLE"[..] } else { &b"FORGET-SCOPED"[..] }, id.as_bytes()];
        args.extend(self.scope.args());
        match Self::call(&mut self.wire, &args)? {
            Reply::Int(0) => Ok(false), Reply::Int(1) => Ok(true),
            got => Err(unexpected("AIMEM forget :0 or :1", got)),
        }
    }

    pub fn forget_receipt(&mut self, id: &str, key: &str) -> Result<DurableReceipt, ControllerError> {
        if id.is_empty() || key.is_empty() { return Err(ControllerError::InvalidConfig("AIMEM forget receipt requires id and retry key")); }
        let mut args = vec![&b"FORGET-SCOPED-RECEIPT"[..], id.as_bytes()];
        args.extend(self.scope.args());
        args.push(key.as_bytes());
        receipt(Self::call(&mut self.wire, &args)?, "FORGET-SCOPED")
    }

    pub fn count(&mut self, kind: u8) -> Result<u64, ControllerError> {
        if kind > 2 { return Err(ControllerError::InvalidConfig("invalid AIMEM kind")); }
        let kind = kind.to_string();
        let mut args = vec![&b"COUNT-SCOPED"[..]];
        args.extend(self.scope.args());
        args.push(kind.as_bytes());
        match Self::call(&mut self.wire, &args)? {
            Reply::Int(n) if n >= 0 => Ok(n as u64),
            got => Err(unexpected("nonnegative AIMEM count", got)),
        }
    }

    pub fn event_append(&mut self, producer: &str, event_id: &str, kind: &str, source_ms: u64, summary: &str, evidence_id: Option<&str>) -> Result<String, ControllerError> {
        let time = source_ms.to_string();
        let mut args = vec![&b"EVENT"[..], &b"APPEND"[..]];
        args.extend(self.scope.args());
        args.extend([producer.as_bytes(), event_id.as_bytes(), kind.as_bytes(), time.as_bytes(), summary.as_bytes()]);
        if let Some(id) = evidence_id { args.push(id.as_bytes()); }
        text(Self::call(&mut self.wire, &args)?)
    }

    pub fn event_get(&mut self, id: &str) -> Result<Option<MemoryHit>, ControllerError> {
        let mut args = vec![&b"EVENT"[..], &b"READ"[..], id.as_bytes()];
        args.extend(self.scope.args());
        match Self::call(&mut self.wire, &args)? { Reply::Nil => Ok(None), r => hit(r).map(Some) }
    }
}
