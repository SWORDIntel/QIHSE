//! Pure-`std` controller client for the QIHSE federation surface
//! (CITADEL v3 §25 — the Rust half of the controller SDK).
//!
//! This module is a synchronous RESP client over [`std::net::TcpStream`] with
//! named wrappers mirroring the C reference client
//! (`include/qihse_controller.h` / `src/controller/qihse_controller.c`):
//! no FFI, no `unsafe`, no async runtime, and no dependencies beyond `std`.
//!
//! # Authority model
//!
//! The client confers no authority. Credentials are an explicit parameter of
//! [`ControllerClient::connect`]; there are no ambient credentials, no
//! environment fallbacks, and no client-side authorization shortcuts. Every
//! invariant (authentication, scopes, classification, replay) is enforced by
//! the server — a denied call surfaces as [`ControllerError::Server`] with the
//! server's error class and message, never as fabricated data.
//!
//! # Wire bounds
//!
//! Replies are decoded with hard caps mirroring the C client, so a hostile or
//! corrupt peer cannot turn the decoder into a memory sink:
//!
//! | Bound          | Default          | Violation                             |
//! |----------------|------------------|---------------------------------------|
//! | bulk payload   | [`MAX_BULK`] 16 MiB | [`ControllerError::OversizedBulk`] |
//! | array items    | [`MAX_ITEMS`] 1 Mi items | [`ControllerError::TooManyItems`] |
//! | nesting depth  | [`MAX_DEPTH`] 32 | [`ControllerError::TooDeep`]          |
//!
//! Outbound commands whose encoded size would exceed [`MAX_BULK`] are rejected
//! before the socket is touched with [`ControllerError::CommandTooLarge`].
//! All bound violations are errors, never panics.
//!
//! # Watches
//!
//! [`Watch`] is a stateful cursor over the server's event journal. `next`
//! delivers events and remembers the highest delivered offset; `ack` tells the
//! server it may drop the backlog up to that offset; `reopen` re-opens the
//! watch after a reconnect and rewinds it to the last acked cursor, giving
//! at-least-once delivery across connection loss.

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Hard cap on a single bulk payload (16 MiB), mirroring `QIHSE_CTRL_MAX_BULK`.
pub const MAX_BULK: usize = 16 * 1024 * 1024;
/// Hard cap on the number of items in one reply array (1 Mi), mirroring
/// `QIHSE_CTRL_MAX_ITEMS`.
pub const MAX_ITEMS: usize = 1 << 20;
/// Hard cap on reply nesting depth (32), mirroring `QIHSE_CTRL_MAX_DEPTH`.
pub const MAX_DEPTH: usize = 32;
/// Default socket timeout, mirroring `QIHSE_CTRL_DEFAULT_TIMEOUT_MS`.
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;

const RX_CAP: usize = 64 * 1024;
const LINE_CAP: usize = 128;
const FEDERATION: &[u8] = b"FEDERATION";

// ============================================================================
// Errors
// ============================================================================

/// Typed error for every failure the controller client can report. A server
/// denial carries the server's error class (`NOPERM`, `ERR`, …) and message
/// verbatim; bound violations identify the limit that was exceeded.
#[derive(Debug)]
pub enum ControllerError {
    /// Bad client configuration (empty host, zero port, …).
    InvalidConfig(&'static str),
    /// Underlying socket I/O error (other than a timeout).
    Transport(io::Error),
    /// The read/write deadline elapsed. Like the C client, a timed-out
    /// connection is marked dead and must be re-established.
    Timeout,
    /// The peer closed the connection, or a previous failure already marked
    /// this connection dead.
    Closed,
    /// The server replied `-CLASS message` (denial or protocol-level error).
    Server { class: String, message: String },
    /// Malformed RESP: bad type byte, bad integer, missing CRLF, overlong line.
    Protocol(String),
    /// A reply declared a bulk payload larger than [`MAX_BULK`].
    OversizedBulk { declared: usize },
    /// A reply declared more array items than [`MAX_ITEMS`].
    TooManyItems { declared: i64 },
    /// A reply nested deeper than [`MAX_DEPTH`].
    TooDeep { depth: usize },
    /// An outbound command would encode to more than [`MAX_BULK`] bytes; it is
    /// rejected before anything is written and the connection stays usable.
    CommandTooLarge { bytes: usize },
    /// A typed wrapper received a reply of the wrong shape.
    UnexpectedReply {
        expected: &'static str,
        got: Reply,
    },
}

impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControllerError::InvalidConfig(m) => {
                write!(f, "invalid controller client configuration: {m}")
            }
            ControllerError::Transport(e) => write!(f, "transport error: {e}"),
            ControllerError::Timeout => write!(
                f,
                "timed out waiting for the controller (connection is now dead)"
            ),
            ControllerError::Closed => write!(
                f,
                "connection closed by peer or previously failed; reconnect to continue"
            ),
            ControllerError::Server { class, message } => {
                if message.is_empty() {
                    write!(f, "server error: -{class}")
                } else {
                    write!(f, "server error: -{class} {message}")
                }
            }
            ControllerError::Protocol(m) => write!(f, "malformed reply: {m}"),
            ControllerError::OversizedBulk { declared } => write!(
                f,
                "declared bulk length {declared} exceeds the {MAX_BULK}-byte decoder cap"
            ),
            ControllerError::TooManyItems { declared } => write!(
                f,
                "declared array length {declared} exceeds the {MAX_ITEMS}-item decoder cap"
            ),
            ControllerError::TooDeep { depth } => write!(
                f,
                "reply nesting depth {depth} exceeds the {MAX_DEPTH}-level decoder cap"
            ),
            ControllerError::CommandTooLarge { bytes } => write!(
                f,
                "encoded command is ~{bytes} bytes, over the {MAX_BULK}-byte send cap"
            ),
            ControllerError::UnexpectedReply { expected, got } => {
                write!(f, "unexpected reply shape: expected {expected}, got {got:?}")
            }
        }
    }
}

impl std::error::Error for ControllerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ControllerError::Transport(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ControllerError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            // Linux surfaces SO_RCVTIMEO expiry as EAGAIN/WouldBlock; other
            // platforms raise TimedOut. Both mean the deadline elapsed.
            ErrorKind::WouldBlock | ErrorKind::TimedOut => ControllerError::Timeout,
            _ => ControllerError::Transport(e),
        }
    }
}

// ============================================================================
// Reply model
// ============================================================================

/// A decoded RESP reply, mirroring `qihse_ctrl_reply_t`.
///
/// Error replies inside a nested array stay as [`Reply::Error`]; a top-level
/// error reply is converted to [`ControllerError::Server`] by
/// [`ControllerClient::call`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// `+text` — simple string.
    Simple(String),
    /// `-CLASS message` — server error (class = first whitespace-delimited
    /// token, message = the remainder).
    Error { class: String, message: String },
    /// `:n` — integer.
    Int(i64),
    /// `$len` — bulk payload, byte-exact (may contain NUL/CRLF).
    Bulk(Vec<u8>),
    /// `$-1` / `*-1` — null.
    Nil,
    /// `*n` — array of nested replies.
    Array(Vec<Reply>),
}

impl Reply {
    /// True for a `+OK` simple reply (mirrors `qihse_ctrl_reply_ok`).
    pub fn is_ok(&self) -> bool {
        matches!(self, Reply::Simple(s) if s == "OK")
    }

    /// Payload bytes for simple/bulk replies, else `None`.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Reply::Simple(s) => Some(s.as_bytes()),
            Reply::Bulk(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    /// UTF-8 text for simple/bulk replies, else `None`.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Reply::Simple(s) => Some(s),
            Reply::Bulk(b) => std::str::from_utf8(b).ok(),
            _ => None,
        }
    }

    /// Integer value for int replies, else `None`.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Reply::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Items for array replies, else `None`.
    pub fn as_array(&self) -> Option<&[Reply]> {
        match self {
            Reply::Array(items) => Some(items),
            _ => None,
        }
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reply::Simple(s) => write!(f, "+{s}"),
            Reply::Error { class, message } => {
                if message.is_empty() {
                    write!(f, "-{class}")
                } else {
                    write!(f, "-{class} {message}")
                }
            }
            Reply::Int(n) => write!(f, ":{n}"),
            Reply::Bulk(b) => write!(f, "$({} bytes)", b.len()),
            Reply::Nil => write!(f, "nil"),
            Reply::Array(items) => write!(f, "array({} items)", items.len()),
        }
    }
}

/// Split `-CLASS message` text into (class, message). The class is everything
/// before the first ASCII whitespace; the message is the verbatim remainder.
fn split_error(text: &str) -> (String, String) {
    match text.find(|c: char| c.is_ascii_whitespace()) {
        Some(i) => (text[..i].to_string(), text[i + 1..].to_string()),
        None => (text.to_string(), String::new()),
    }
}

// ============================================================================
// Configuration / credentials
// ============================================================================

/// Explicit authentication material for [`ControllerClient::connect`].
///
/// There is deliberately no ambient-credential fallback: connecting without
/// credentials is represented by [`Credentials::Unauthenticated`], and what an
/// unauthenticated session may do is decided entirely by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credentials {
    /// Connect without authenticating (server decides what this may do).
    Unauthenticated,
    /// Authenticate with `AUTH <username> <password>` immediately after
    /// connecting; a refused AUTH fails [`ControllerClient::connect`].
    Password {
        /// Principal name.
        username: String,
        /// Secret for the principal.
        password: String,
    },
}

/// Connection parameters, mirroring `qihse_controller_config_t`.
#[derive(Debug, Clone)]
pub struct ControllerConfig {
    /// Controller host (e.g. `"127.0.0.1"`); resolved with `ToSocketAddrs`.
    pub host: String,
    /// Controller RESP port.
    pub port: u16,
    /// Explicit credentials — never read from the environment.
    pub credentials: Credentials,
    /// Read/write deadline for each round-trip; zero means
    /// [`DEFAULT_TIMEOUT_MS`].
    pub timeout: Duration,
}

impl ControllerConfig {
    /// Configuration for `host:port` with the given explicit credentials and
    /// the default timeout.
    pub fn new(host: impl Into<String>, port: u16, credentials: Credentials) -> Self {
        Self {
            host: host.into(),
            port,
            credentials,
            timeout: Duration::ZERO,
        }
    }
}

// ============================================================================
// Bounded wire reader
// ============================================================================

/// Buffered reader over any [`Read`] source. Generic so the decoder can be
/// unit-tested on in-memory input; the client instantiates it with a
/// [`TcpStream`].
struct Wire<R: Read> {
    stream: R,
    buf: Vec<u8>,
    pos: usize,
    end: usize,
}

impl<R: Read> Wire<R> {
    fn new(stream: R) -> Self {
        Self {
            stream,
            buf: vec![0u8; RX_CAP],
            pos: 0,
            end: 0,
        }
    }

    /// Pull more bytes into the buffer, compacting when needed. Returns the
    /// number of bytes read (0 = EOF).
    fn fill(&mut self) -> Result<usize, ControllerError> {
        if self.pos == self.end {
            self.pos = 0;
            self.end = 0;
        } else if self.end == self.buf.len() {
            // Unreachable through read_line (LINE_CAP guard) and read_bytes
            // (always drains first), but rejected defensively rather than
            // relying on the invariant.
            if self.pos == 0 {
                return Err(ControllerError::Protocol(
                    "rx buffer full with no delimiter".to_string(),
                ));
            }
            self.buf.copy_within(self.pos..self.end, 0);
            self.end -= self.pos;
            self.pos = 0;
        }
        let n = self.stream.read(&mut self.buf[self.end..])?;
        self.end += n;
        Ok(n)
    }

    /// Read one CRLF-terminated line (terminator consumed, CR stripped).
    /// Mirrors the C client's 128-byte line cap: a longer line is a protocol
    /// error, never an unbounded allocation.
    fn read_line(&mut self) -> Result<Vec<u8>, ControllerError> {
        loop {
            if let Some(i) = self.buf[self.pos..self.end]
                .iter()
                .position(|&b| b == b'\n')
            {
                let mut line = self.buf[self.pos..self.pos + i].to_vec();
                self.pos += i + 1;
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            if self.end - self.pos >= LINE_CAP {
                return Err(ControllerError::Protocol(format!(
                    "reply line longer than {} bytes",
                    LINE_CAP - 1
                )));
            }
            if self.fill()? == 0 {
                return Err(ControllerError::Closed);
            }
        }
    }

    /// Read exactly `len` bytes (caller guarantees `len <= MAX_BULK`).
    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, ControllerError> {
        let mut out = vec![0u8; len];
        let mut got = 0;
        while got < len {
            let avail = self.end - self.pos;
            if avail > 0 {
                let take = avail.min(len - got);
                out[got..got + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
                self.pos += take;
                got += take;
            } else if self.fill()? == 0 {
                return Err(ControllerError::Closed);
            }
        }
        Ok(out)
    }
}

// ============================================================================
// Decoder
// ============================================================================

/// Decode one reply with the C client's bounds. Depth is tracked so nesting
/// past [`MAX_DEPTH`] is rejected before it can consume stack.
fn parse_reply<R: Read>(w: &mut Wire<R>, depth: usize) -> Result<Reply, ControllerError> {
    if depth > MAX_DEPTH {
        return Err(ControllerError::TooDeep { depth });
    }
    let line = w.read_line()?;
    let (&tag, rest) = line
        .split_first()
        .ok_or_else(|| ControllerError::Protocol("empty reply line".to_string()))?;
    let rest = String::from_utf8_lossy(rest).into_owned();
    match tag {
        b'+' => Ok(Reply::Simple(rest)),
        b'-' => {
            let (class, message) = split_error(&rest);
            Ok(Reply::Error { class, message })
        }
        b':' => rest
            .parse::<i64>()
            .map(Reply::Int)
            .map_err(|_| ControllerError::Protocol(format!("bad integer reply {rest:?}"))),
        b'$' => {
            let len = parse_len(&rest, "bulk")?;
            if len < 0 {
                return Ok(Reply::Nil);
            }
            if len as usize > MAX_BULK {
                return Err(ControllerError::OversizedBulk {
                    declared: len as usize,
                });
            }
            let data = w.read_bytes(len as usize)?;
            let crlf = w.read_bytes(2)?;
            if crlf != b"\r\n" {
                return Err(ControllerError::Protocol(
                    "missing CRLF after bulk payload".to_string(),
                ));
            }
            Ok(Reply::Bulk(data))
        }
        b'*' => {
            let count = parse_len(&rest, "array")?;
            if count < 0 {
                return Ok(Reply::Nil);
            }
            if count as usize > MAX_ITEMS {
                return Err(ControllerError::TooManyItems { declared: count });
            }
            // Same acceptance bound as the C client, but the eager allocation
            // is capped so a lying `*<MAX_ITEMS>` header cannot amplify a
            // few wire bytes into a huge allocation; growth is organic.
            let mut items = Vec::with_capacity((count as usize).min(4096));
            for _ in 0..count {
                items.push(parse_reply(w, depth + 1)?);
            }
            Ok(Reply::Array(items))
        }
        other => Err(ControllerError::Protocol(format!(
            "unknown reply type byte {other:#02x}"
        ))),
    }
}

fn parse_len(rest: &str, what: &'static str) -> Result<i64, ControllerError> {
    rest.parse::<i64>()
        .map_err(|_| ControllerError::Protocol(format!("bad {what} length {rest:?}")))
}

// ============================================================================
// Encoder
// ============================================================================

/// Append the decimal form of `n` without `format!` machinery.
fn push_u64(buf: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    buf.extend_from_slice(&tmp[i..]);
}

/// Encode `args` as a RESP command (`*N` + `$len` frames). The total encoded
/// size is bounded by [`MAX_BULK`] before any allocation, mirroring the C
/// client's pre-send size check.
fn encode_command(args: &[&[u8]]) -> Result<Vec<u8>, ControllerError> {
    let mut total: usize = 32;
    for a in args {
        total = total.saturating_add(a.len().saturating_add(34));
        if total > MAX_BULK {
            return Err(ControllerError::CommandTooLarge { bytes: total });
        }
    }
    let mut out = Vec::with_capacity(total.min(MAX_BULK));
    out.push(b'*');
    push_u64(&mut out, args.len() as u64);
    out.extend_from_slice(b"\r\n");
    for a in args {
        out.push(b'$');
        push_u64(&mut out, a.len() as u64);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
    Ok(out)
}

// ============================================================================
// Client
// ============================================================================

/// Synchronous, bounded RESP controller client (the Rust mirror of
/// `qihse_controller_t`). Holds one TCP connection; any transport failure,
/// timeout, or decoding bound violation marks it dead — reconnect with
/// [`ControllerClient::connect`] and re-open watches with [`Watch::reopen`].
pub struct ControllerClient {
    wire: Wire<TcpStream>,
    dead: bool,
}

impl fmt::Debug for ControllerClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControllerClient")
            .field("connected", &!self.dead)
            .finish()
    }
}

impl ControllerClient {
    /// Resolve, connect, apply the timeout, and — when credentials are
    /// supplied — authenticate with `AUTH <username> <password>`. Refused
    /// credentials surface as [`ControllerError::Server`]; an unreachable
    /// controller as [`ControllerError::Transport`].
    pub fn connect(config: &ControllerConfig) -> Result<Self, ControllerError> {
        if config.host.is_empty() {
            return Err(ControllerError::InvalidConfig("host must not be empty"));
        }
        if config.port == 0 {
            return Err(ControllerError::InvalidConfig("port must not be zero"));
        }
        let timeout = if config.timeout.is_zero() {
            Duration::from_millis(DEFAULT_TIMEOUT_MS)
        } else {
            config.timeout
        };

        let addrs: Vec<_> = (config.host.as_str(), config.port)
            .to_socket_addrs()
            .map_err(ControllerError::from)?
            .collect();
        if addrs.is_empty() {
            return Err(ControllerError::InvalidConfig(
                "host did not resolve to any address",
            ));
        }

        let mut last_err = None;
        let mut stream = None;
        for addr in &addrs {
            match TcpStream::connect_timeout(addr, timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last_err = Some(ControllerError::Transport(e)),
            }
        }
        let stream = match stream {
            Some(s) => s,
            None => {
                return Err(last_err
                    .unwrap_or(ControllerError::InvalidConfig("connect failed")))
            }
        };
        let _ = stream.set_nodelay(true);
        stream
            .set_read_timeout(Some(timeout))
            .map_err(ControllerError::from)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(ControllerError::from)?;

        let mut client = Self {
            wire: Wire::new(stream),
            dead: false,
        };

        if let Credentials::Password { username, password } = &config.credentials {
            let reply = client.call(&[b"AUTH", username.as_bytes(), password.as_bytes()])?;
            if !reply.is_ok() {
                return Err(ControllerError::UnexpectedReply {
                    expected: "+OK for AUTH",
                    got: reply,
                });
            }
        }
        Ok(client)
    }

    /// True while the connection is usable (mirrors
    /// `qihse_controller_connected`).
    pub fn is_connected(&self) -> bool {
        !self.dead
    }

    /// Generic escape hatch (mirrors `qihse_ctrl_callv`): send an arbitrary
    /// command as byte-exact arguments and decode one bounded reply. A
    /// top-level `-CLASS message` reply becomes
    /// [`ControllerError::Server`]; transport failures, timeouts and bound
    /// violations mark the connection dead.
    pub fn call(&mut self, args: &[&[u8]]) -> Result<Reply, ControllerError> {
        if self.dead {
            return Err(ControllerError::Closed);
        }
        if args.is_empty() {
            return Err(ControllerError::InvalidConfig("command must have arguments"));
        }
        let frame = encode_command(args)?; // CommandTooLarge leaves the connection usable
        if let Err(e) = self.wire.stream.write_all(&frame) {
            self.dead = true;
            return Err(ControllerError::from(e));
        }
        match parse_reply(&mut self.wire, 0) {
            Ok(Reply::Error { class, message }) => Err(ControllerError::Server { class, message }),
            Ok(reply) => Ok(reply),
            Err(e) => {
                self.dead = true;
                Err(e)
            }
        }
    }

    /// Prepend `FEDERATION` and forward string arguments (mirrors the C
    /// client's `fed_call`).
    fn call_fed(&mut self, sub: &str, args: &[&str]) -> Result<Reply, ControllerError> {
        let mut argv: Vec<&[u8]> = Vec::with_capacity(args.len() + 2);
        argv.push(FEDERATION);
        argv.push(sub.as_bytes());
        for a in args {
            argv.push(a.as_bytes());
        }
        self.call(&argv)
    }

    // ── Typed reply helpers ────────────────────────────────────────────

    fn require_int(reply: Reply, expected: &'static str) -> Result<i64, ControllerError> {
        match reply {
            Reply::Int(n) => Ok(n),
            got => Err(ControllerError::UnexpectedReply { expected, got }),
        }
    }

    fn require_u64(reply: Reply, expected: &'static str) -> Result<u64, ControllerError> {
        let n = Self::require_int(reply, expected)?;
        if n >= 0 {
            Ok(n as u64)
        } else {
            Err(ControllerError::UnexpectedReply {
                expected,
                got: Reply::Int(n),
            })
        }
    }

    fn require_u32(reply: Reply, expected: &'static str) -> Result<u32, ControllerError> {
        let n = Self::require_u64(reply, expected)?;
        n.try_into().map_err(|_| ControllerError::UnexpectedReply {
            expected,
            got: Reply::Int(n as i64),
        })
    }

    fn require_bool(reply: Reply, expected: &'static str) -> Result<bool, ControllerError> {
        match reply {
            Reply::Int(0) => Ok(false),
            Reply::Int(1) => Ok(true),
            got => Err(ControllerError::UnexpectedReply { expected, got }),
        }
    }

    fn require_ok(reply: Reply, expected: &'static str) -> Result<(), ControllerError> {
        if reply.is_ok() {
            Ok(())
        } else {
            Err(ControllerError::UnexpectedReply { expected, got: reply })
        }
    }

    // ── §25: Node inventory and trust ──────────────────────────────────

    /// `FEDERATION NODE.LIST` → array of triples `[node_uuid, trust_state,
    /// identity_kind]`. Mirrors `qihse_ctrl_node_list`.
    pub fn node_list(&mut self) -> Result<Reply, ControllerError> {
        self.call_fed("NODE.LIST", &[])
    }

    /// `FEDERATION NODE.SHOW <uuid>` → `[hostname, trust, kind, scopes,
    /// enroll_epoch, capabilities, fingerprint_hex, key_handle, sig_alg,
    /// pubkey_len]`. Mirrors `qihse_ctrl_node_get`.
    pub fn node_get(&mut self, node_uuid: &str) -> Result<Reply, ControllerError> {
        self.call_fed("NODE.SHOW", &[node_uuid])
    }

    /// `FEDERATION NODE.ENROLL <identity_kind> <hostname> <boot_id>` → the
    /// new node UUID (bulk). Mirrors `qihse_ctrl_node_enroll`.
    pub fn node_enroll(
        &mut self,
        identity_kind: &str,
        hostname: &str,
        boot_id: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed("NODE.ENROLL", &[identity_kind, hostname, boot_id])
    }

    /// `FEDERATION NODE.APPROVE <uuid> [epoch]` → `+OK`. `enrollment_epoch`
    /// of 0 lets the server assign one. Mirrors `qihse_ctrl_node_approve`.
    pub fn node_approve(
        &mut self,
        node_uuid: &str,
        enrollment_epoch: u64,
    ) -> Result<Reply, ControllerError> {
        let epoch = enrollment_epoch.to_string();
        let args = if enrollment_epoch == 0 {
            vec![node_uuid]
        } else {
            vec![node_uuid, epoch.as_str()]
        };
        self.call_fed("NODE.APPROVE", &args)
    }

    /// `FEDERATION NODE.REVOKE <uuid>` → `+OK`. Mirrors `qihse_ctrl_node_revoke`.
    pub fn node_revoke(&mut self, node_uuid: &str) -> Result<Reply, ControllerError> {
        self.call_fed("NODE.REVOKE", &[node_uuid])
    }

    /// `FEDERATION TRUST.SET <uuid> <trust_state> <result>` → `+OK`.
    /// Mirrors `qihse_ctrl_trust_set`.
    pub fn trust_set(
        &mut self,
        node_uuid: &str,
        trust_state: &str,
        result: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed("TRUST.SET", &[node_uuid, trust_state, result])
    }

    /// `FEDERATION TRUST.STATES` → array of state names. Mirrors
    /// `qihse_ctrl_trust_states`.
    pub fn trust_states(&mut self) -> Result<Reply, ControllerError> {
        self.call_fed("TRUST.STATES", &[])
    }

    /// `FEDERATION TRUST.ADMISSION <uuid>` → the admission verdict array.
    /// Mirrors `qihse_ctrl_trust_admission`.
    pub fn trust_admission(&mut self, node_uuid: &str) -> Result<Reply, ControllerError> {
        self.call_fed("TRUST.ADMISSION", &[node_uuid])
    }

    // ── §25: Namespaces and replication groups ────────────────────────

    /// `FEDERATION NS.REGISTER <name> <consistency> [authority]` → `+OK`.
    /// `consistency` is a case-sensitive class name (`LOCAL`, `EVENTUAL`,
    /// `CAUSAL`, `QUORUM`, `LINEARIZABLE`); `authority_node_uuid` of `None`
    /// means this node. Mirrors `qihse_ctrl_ns_register`.
    pub fn ns_register(
        &mut self,
        name: &str,
        consistency: &str,
        authority_node_uuid: Option<&str>,
    ) -> Result<Reply, ControllerError> {
        let mut args = vec![name, consistency];
        if let Some(auth) = authority_node_uuid {
            args.push(auth);
        }
        self.call_fed("NS.REGISTER", &args)
    }

    /// `FEDERATION NS.UNREGISTER <name>` → `+OK`. Mirrors
    /// `qihse_ctrl_ns_unregister`.
    pub fn ns_unregister(&mut self, name: &str) -> Result<Reply, ControllerError> {
        self.call_fed("NS.UNREGISTER", &[name])
    }

    /// `FEDERATION NS.LIST` → array of namespaces. Mirrors `qihse_ctrl_ns_list`.
    pub fn ns_list(&mut self) -> Result<Reply, ControllerError> {
        self.call_fed("NS.LIST", &[])
    }

    /// `FEDERATION NS.WRITABLE <name>` → `:1`/`:0` — can this principal write
    /// the namespace now? Mirrors `qihse_ctrl_ns_writable`.
    pub fn ns_writable(&mut self, name: &str) -> Result<bool, ControllerError> {
        let reply = self.call_fed("NS.WRITABLE", &[name])?;
        Self::require_bool(reply, ":1/:0 NS.WRITABLE verdict")
    }

    /// `FEDERATION MANIFEST <ns>` → the namespace anti-entropy manifest
    /// (range digests). Mirrors `qihse_ctrl_manifest`.
    pub fn manifest(&mut self, ns: &str) -> Result<Reply, ControllerError> {
        self.call_fed("MANIFEST", &[ns])
    }

    /// `FEDERATION GROUP.CREATE <group_id> [consistency]` → `+OK`.
    /// `consistency` of `None` selects the server default (`QUORUM`).
    /// Mirrors `qihse_ctrl_group_create`.
    pub fn group_create(
        &mut self,
        group_id: &str,
        consistency: Option<&str>,
    ) -> Result<Reply, ControllerError> {
        let mut args = vec![group_id];
        if let Some(c) = consistency {
            args.push(c);
        }
        self.call_fed("GROUP.CREATE", &args)
    }

    /// `FEDERATION GROUP.ADD <group_id> <member_uuid> [voter] [witness]` →
    /// `+OK`; the `voter`/`witness` tokens are appended only when set.
    /// Mirrors `qihse_ctrl_group_add`.
    pub fn group_add(
        &mut self,
        group_id: &str,
        member_uuid: &str,
        voter: bool,
        witness: bool,
    ) -> Result<Reply, ControllerError> {
        let mut args = vec![group_id, member_uuid];
        if voter {
            args.push("voter");
        }
        if witness {
            args.push("witness");
        }
        self.call_fed("GROUP.ADD", &args)
    }

    /// `FEDERATION GROUP.REMOVE <group_id> <member_uuid>` → `+OK`. Mirrors
    /// `qihse_ctrl_group_remove`.
    pub fn group_remove(
        &mut self,
        group_id: &str,
        member_uuid: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed("GROUP.REMOVE", &[group_id, member_uuid])
    }

    /// `FEDERATION GROUP.SHOW <group_id>` → the group record. Mirrors
    /// `qihse_ctrl_group_show`.
    pub fn group_show(&mut self, group_id: &str) -> Result<Reply, ControllerError> {
        self.call_fed("GROUP.SHOW", &[group_id])
    }

    /// `FEDERATION GROUP.LIST` → group ids. Mirrors `qihse_ctrl_group_list`.
    pub fn group_list(&mut self) -> Result<Reply, ControllerError> {
        self.call_fed("GROUP.LIST", &[])
    }

    /// `FEDERATION GROUP.ADVANCE <group_id>` → `:new term`. Mirrors
    /// `qihse_ctrl_group_advance`.
    pub fn group_advance(&mut self, group_id: &str) -> Result<Reply, ControllerError> {
        self.call_fed("GROUP.ADVANCE", &[group_id])
    }

    // ── §25: Object / desired-vs-observed ─────────────────────────────

    /// `FEDERATION OBJECT.GET <ns> <rid>` → array `[generation, value]`.
    /// Mirrors `qihse_ctrl_object_get`.
    pub fn object_get(&mut self, ns: &str, resource_id: &str) -> Result<Reply, ControllerError> {
        self.call_fed("OBJECT.GET", &[ns, resource_id])
    }

    /// `FEDERATION OBJECT.CAS <ns> <rid> <value> <expected_generation>` →
    /// `:1` on swap, `:0` on generation mismatch. The precondition is an
    /// explicit [`CasPrecondition`]; the value is byte-exact. Mirrors
    /// `qihse_ctrl_object_cas`.
    pub fn object_cas(
        &mut self,
        ns: &str,
        resource_id: &str,
        value: &[u8],
        precondition: CasPrecondition,
    ) -> Result<bool, ControllerError> {
        let gen = match precondition {
            CasPrecondition::CreateOnly => "0".to_string(),
            CasPrecondition::IfGenerationIs(g) => g.to_string(),
        };
        let reply = self.call(&[
            FEDERATION,
            b"OBJECT.CAS",
            ns.as_bytes(),
            resource_id.as_bytes(),
            value,
            gen.as_bytes(),
        ])?;
        Self::require_bool(reply, ":1/:0 OBJECT.CAS verdict")
    }

    // ── §25: Lease / epoch ────────────────────────────────────────────

    /// `FEDERATION LEASE.ACQUIRE <ns> <rid> <fencing_epoch> [expires_ms]` →
    /// bulk lease UUID. `expires_ms` of 0 selects the server default.
    /// Mirrors `qihse_ctrl_lease_acquire`.
    pub fn lease_acquire(
        &mut self,
        ns: &str,
        resource_id: &str,
        fencing_epoch: u64,
        expires_ms: u64,
    ) -> Result<Reply, ControllerError> {
        let epoch = fencing_epoch.to_string();
        let expires = expires_ms.to_string();
        let args = if expires_ms == 0 {
            vec![ns, resource_id, epoch.as_str()]
        } else {
            vec![ns, resource_id, epoch.as_str(), expires.as_str()]
        };
        self.call_fed("LEASE.ACQUIRE", &args)
    }

    /// `FEDERATION LEASE.READ <lease_id>` → `[resource_id, state,
    /// fencing_epoch, generation, expires_hlc_physical]`. Mirrors
    /// `qihse_ctrl_lease_read`.
    pub fn lease_read(&mut self, lease_id: &str) -> Result<Reply, ControllerError> {
        self.call_fed("LEASE.READ", &[lease_id])
    }

    /// `FEDERATION LEASE.RENEW <lease_id> <expires_ms>` → `+OK`. Mirrors
    /// `qihse_ctrl_lease_renew`.
    pub fn lease_renew(
        &mut self,
        lease_id: &str,
        expires_ms: u64,
    ) -> Result<Reply, ControllerError> {
        let expires = expires_ms.to_string();
        self.call_fed("LEASE.RENEW", &[lease_id, expires.as_str()])
    }

    /// `FEDERATION LEASE.RELEASE <lease_id>` → `+OK`. Mirrors
    /// `qihse_ctrl_lease_release`.
    pub fn lease_release(&mut self, lease_id: &str) -> Result<Reply, ControllerError> {
        self.call_fed("LEASE.RELEASE", &[lease_id])
    }

    /// `FEDERATION EPOCH.NEXT` → `:new fencing epoch`. Mirrors
    /// `qihse_ctrl_epoch_next`.
    pub fn epoch_next(&mut self) -> Result<u64, ControllerError> {
        let reply = self.call_fed("EPOCH.NEXT", &[])?;
        Self::require_u64(reply, ":integer EPOCH.NEXT")
    }

    /// `FEDERATION EPOCH.CURRENT` → `:current fencing epoch`. Mirrors
    /// `qihse_ctrl_epoch_current`.
    pub fn epoch_current(&mut self) -> Result<u64, ControllerError> {
        let reply = self.call_fed("EPOCH.CURRENT", &[])?;
        Self::require_u64(reply, ":integer EPOCH.CURRENT")
    }

    // ── §25: Event journal ────────────────────────────────────────────

    /// `FEDERATION EVENT.APPEND <type> <rid> [payload]` → `:journal offset`
    /// (the resumable cursor). The payload is transmitted byte-exact; `None`
    /// omits it. Mirrors `qihse_ctrl_event_append`.
    pub fn event_append(
        &mut self,
        event_type: &str,
        resource_id: &str,
        payload: Option<&[u8]>,
    ) -> Result<u64, ControllerError> {
        let reply = match payload {
            Some(p) => self.call(&[
                FEDERATION,
                b"EVENT.APPEND",
                event_type.as_bytes(),
                resource_id.as_bytes(),
                p,
            ])?,
            None => self.call_fed("EVENT.APPEND", &[event_type, resource_id])?,
        };
        Self::require_u64(reply, ":integer EVENT.APPEND offset")
    }

    /// `FEDERATION EVENT.REPLAY <from_cursor>` → flat array of triples
    /// `[offset, event_type, resource_id]`; `0` starts at the journal start.
    /// Mirrors `qihse_ctrl_event_replay`.
    pub fn event_replay(&mut self, from_cursor: u64) -> Result<Reply, ControllerError> {
        let cursor = from_cursor.to_string();
        self.call_fed("EVENT.REPLAY", &[cursor.as_str()])
    }

    // ── §25: Resumable watches ────────────────────────────────────────

    /// Open a stateful [`Watch`] (`FEDERATION WATCH.OPEN [prefix]`). The
    /// prefix is a resource-id filter (`"vm-"` receives only events for
    /// resources under it); `None` receives all events. Mirrors
    /// `qihse_ctrl_watch_open` plus the client-side cursor.
    pub fn watch_open(&mut self, prefix: Option<&str>) -> Result<Watch, ControllerError> {
        let id = self.watch_open_id(prefix)?;
        Ok(Watch {
            id,
            prefix: prefix.map(str::to_string),
            acked: 0,
            delivered: 0,
        })
    }

    fn watch_open_id(&mut self, prefix: Option<&str>) -> Result<u32, ControllerError> {
        let reply = match prefix {
            Some(p) => self.call_fed("WATCH.OPEN", &[p])?,
            None => self.call_fed("WATCH.OPEN", &[])?,
        };
        Self::require_u32(reply, ":integer watch id")
    }

    /// `FEDERATION WATCH.NEXT <watch_id>` → `:0` at journal end (`None`), or
    /// `[offset, event_type, resource_id, payload]` (`Some`). Mirrors
    /// `qihse_ctrl_watch_next` with the reply decoded.
    pub fn watch_next(&mut self, watch_id: u32) -> Result<Option<WatchEvent>, ControllerError> {
        let id = watch_id.to_string();
        let reply = self.call_fed("WATCH.NEXT", &[id.as_str()])?;
        match reply {
            Reply::Int(0) => Ok(None),
            Reply::Array(items) if items.len() == 4 => {
                let offset = match items[0] {
                    Reply::Int(n) if n >= 0 => n as u64,
                    _ => {
                        return Err(ControllerError::UnexpectedReply {
                            expected: "watch event [offset, event_type, resource_id, payload]",
                            got: Reply::Array(items),
                        })
                    }
                };
                let text_of = |r: &Reply| -> Option<String> {
                    r.as_bytes()
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                };
                let (Some(event_type), Some(resource_id)) = (text_of(&items[1]), text_of(&items[2]))
                else {
                    return Err(ControllerError::UnexpectedReply {
                        expected: "watch event [offset, event_type, resource_id, payload]",
                        got: Reply::Array(items),
                    });
                };
                let payload = if let Reply::Bulk(p) = &items[3] {
                    p.clone()
                } else if let Reply::Nil = &items[3] {
                    Vec::new()
                } else {
                    return Err(ControllerError::UnexpectedReply {
                        expected: "watch event [offset, event_type, resource_id, payload]",
                        got: Reply::Array(items),
                    });
                };
                Ok(Some(WatchEvent {
                    offset,
                    event_type,
                    resource_id,
                    payload,
                }))
            }
            got => Err(ControllerError::UnexpectedReply {
                expected: ":0 or [offset, event_type, resource_id, payload]",
                got,
            }),
        }
    }

    /// `FEDERATION WATCH.ACK <watch_id> <offset>` → `+OK` (drops the backlog
    /// up to `offset`). Mirrors `qihse_ctrl_watch_ack`.
    pub fn watch_ack(&mut self, watch_id: u32, offset: u64) -> Result<(), ControllerError> {
        let (id, off) = (watch_id.to_string(), offset.to_string());
        let reply = self.call_fed("WATCH.ACK", &[id.as_str(), off.as_str()])?;
        Self::require_ok(reply, "+OK for WATCH.ACK")
    }

    /// `FEDERATION WATCH.RESUME <watch_id> <cursor>` → `+OK` (rewind to a
    /// cursor, e.g. for a second replay pass). Mirrors
    /// `qihse_ctrl_watch_resume`.
    pub fn watch_resume(&mut self, watch_id: u32, cursor: u64) -> Result<(), ControllerError> {
        let (id, cur) = (watch_id.to_string(), cursor.to_string());
        let reply = self.call_fed("WATCH.RESUME", &[id.as_str(), cur.as_str()])?;
        Self::require_ok(reply, "+OK for WATCH.RESUME")
    }

    // ── §25: Conflicts, status, reconciliation ────────────────────────

    /// `FEDERATION CONFLICT.LIST` → flat array of pairs
    /// `[conflict_uuid, namespace]`. Mirrors `qihse_ctrl_conflict_list`.
    pub fn conflict_list(&mut self) -> Result<Reply, ControllerError> {
        self.call_fed("CONFLICT.LIST", &[])
    }

    /// `FEDERATION CONFLICT.RESOLVE <conflict_uuid> <resolver_uuid>` → `+OK`;
    /// the resolver is an enrolled node id. Mirrors
    /// `qihse_ctrl_conflict_resolve`.
    pub fn conflict_resolve(
        &mut self,
        conflict_uuid: &str,
        resolver_uuid: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed("CONFLICT.RESOLVE", &[conflict_uuid, resolver_uuid])
    }

    /// `FEDERATION STATUS` → bulk status object text (§5 shape). Mirrors
    /// `qihse_ctrl_federation_status`.
    pub fn federation_status(&mut self) -> Result<Reply, ControllerError> {
        self.call_fed("STATUS", &[])
    }

    /// `FEDERATION REJOIN.STATUS <node_uuid>` → `[step, events_transferred,
    /// conflicts_applied, may_publish_ownership, last_error]`. Mirrors
    /// `qihse_ctrl_rejoin_status`.
    pub fn rejoin_status(&mut self, node_uuid: &str) -> Result<Reply, ControllerError> {
        self.call_fed("REJOIN.STATUS", &[node_uuid])
    }

    /// `FEDERATION METRICS [prefix]` → bulk rendered metrics text;
    /// `None` selects all federation metrics. Mirrors `qihse_ctrl_metrics`.
    pub fn metrics(&mut self, prefix: Option<&str>) -> Result<Reply, ControllerError> {
        match prefix {
            Some(p) => self.call_fed("METRICS", &[p]),
            None => self.call_fed("METRICS", &[]),
        }
    }

    // ── §28–§30: Build coordination (STATE ONLY) ──────────────────────

    /// `FEDERATION BUILD.CREATE <package> <revision> <profile> <toolchain>`
    /// → the new build id (bulk). Mirrors `qihse_ctrl_build_job_create`.
    pub fn build_job_create(
        &mut self,
        package: &str,
        revision: &str,
        profile: &str,
        toolchain: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed("BUILD.CREATE", &[package, revision, profile, toolchain])
    }

    /// `FEDERATION BUILD.TRANSITION <build_id> <state> <request_id>
    /// [reason]` → `+OK`; `request_id` is the idempotency key. Mirrors
    /// `qihse_ctrl_build_job_transition`.
    pub fn build_job_transition(
        &mut self,
        build_id: &str,
        state: &str,
        request_id: &str,
        reason: Option<&str>,
    ) -> Result<Reply, ControllerError> {
        let mut args = vec![build_id, state, request_id];
        if let Some(r) = reason {
            args.push(r);
        }
        self.call_fed("BUILD.TRANSITION", &args)
    }

    /// `FEDERATION BUILD.SHOW <build_id>` → the build record. Mirrors
    /// `qihse_ctrl_build_job_get`.
    pub fn build_job_get(&mut self, build_id: &str) -> Result<Reply, ControllerError> {
        self.call_fed("BUILD.SHOW", &[build_id])
    }

    /// `FEDERATION BUILD.LIST` → build records. Mirrors
    /// `qihse_ctrl_build_job_list`.
    pub fn build_job_list(&mut self) -> Result<Reply, ControllerError> {
        self.call_fed("BUILD.LIST", &[])
    }

    /// `FEDERATION BUILD.STATES` → array of state names. Mirrors
    /// `qihse_ctrl_build_states`.
    pub fn build_states(&mut self) -> Result<Reply, ControllerError> {
        self.call_fed("BUILD.STATES", &[])
    }

    /// `FEDERATION BUILDER.CAP <node_uuid> <cores> <ram_gb> <queue_depth>` →
    /// `+OK` (the worker's capability snapshot). Mirrors
    /// `qihse_ctrl_build_worker_publish`.
    pub fn build_worker_publish(
        &mut self,
        node_uuid: &str,
        cores_available: u32,
        ram_available_gb: u32,
        queue_depth: u32,
    ) -> Result<Reply, ControllerError> {
        let (cores, ram, depth) = (
            cores_available.to_string(),
            ram_available_gb.to_string(),
            queue_depth.to_string(),
        );
        self.call_fed(
            "BUILDER.CAP",
            &[node_uuid, cores.as_str(), ram.as_str(), depth.as_str()],
        )
    }

    /// `FEDERATION BUILDER.SHOW <node_uuid>` → the worker record. Mirrors
    /// `qihse_ctrl_build_worker_get`.
    pub fn build_worker_get(&mut self, node_uuid: &str) -> Result<Reply, ControllerError> {
        self.call_fed("BUILDER.SHOW", &[node_uuid])
    }

    // ── §31–§34: Supply chain ─────────────────────────────────────────

    /// `FEDERATION PKG.SET <package> <mode> <reason>` → `+OK`. Mirrors
    /// `qihse_ctrl_pkg_set`.
    pub fn pkg_set(
        &mut self,
        package: &str,
        mode: &str,
        reason: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed("PKG.SET", &[package, mode, reason])
    }

    /// `FEDERATION PKG.GET <package>` → the package record. Mirrors
    /// `qihse_ctrl_pkg_get`.
    pub fn pkg_get(&mut self, package: &str) -> Result<Reply, ControllerError> {
        self.call_fed("PKG.GET", &[package])
    }

    /// `FEDERATION PKG.MODES` → array of registry mode names. Mirrors
    /// `qihse_ctrl_pkg_modes`.
    pub fn pkg_modes(&mut self) -> Result<Reply, ControllerError> {
        self.call_fed("PKG.MODES", &[])
    }

    /// `FEDERATION SUPPLY.SBOM <artifact_digest> <sbom_digest>
    /// <signing_identity> <format>` → `+OK`. Mirrors `qihse_ctrl_supply_sbom`.
    pub fn supply_sbom(
        &mut self,
        artifact_digest: &str,
        sbom_digest: &str,
        signing_identity: &str,
        format: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed(
            "SUPPLY.SBOM",
            &[artifact_digest, sbom_digest, signing_identity, format],
        )
    }

    /// `FEDERATION SUPPLY.SBOM.GET <sbom_digest>` → the record. Mirrors
    /// `qihse_ctrl_supply_sbom_get`.
    pub fn supply_sbom_get(&mut self, sbom_digest: &str) -> Result<Reply, ControllerError> {
        self.call_fed("SUPPLY.SBOM.GET", &[sbom_digest])
    }

    /// `FEDERATION SUPPLY.SNAPSHOT <repository> <digest> <release>
    /// [package_count]` → `+OK`. Mirrors `qihse_ctrl_supply_snapshot`.
    pub fn supply_snapshot(
        &mut self,
        repository: &str,
        digest: &str,
        release: &str,
        package_count: u64,
    ) -> Result<Reply, ControllerError> {
        let count = package_count.to_string();
        let args = if package_count == 0 {
            vec![repository, digest, release]
        } else {
            vec![repository, digest, release, count.as_str()]
        };
        self.call_fed("SUPPLY.SNAPSHOT", &args)
    }

    /// `FEDERATION SUPPLY.SNAPSHOT.LIST [repository]` → array.
    /// Mirrors `qihse_ctrl_supply_snapshot_list`.
    pub fn supply_snapshot_list(
        &mut self,
        repository: Option<&str>,
    ) -> Result<Reply, ControllerError> {
        match repository {
            Some(r) => self.call_fed("SUPPLY.SNAPSHOT.LIST", &[r]),
            None => self.call_fed("SUPPLY.SNAPSHOT.LIST", &[]),
        }
    }

    /// `FEDERATION SUPPLY.VULN <component_digest> <advisory> <severity>
    /// <status>` → `+OK`. Mirrors `qihse_ctrl_supply_vuln`.
    pub fn supply_vuln(
        &mut self,
        component_digest: &str,
        advisory: &str,
        severity: &str,
        status: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed(
            "SUPPLY.VULN",
            &[component_digest, advisory, severity, status],
        )
    }

    /// `FEDERATION SUPPLY.VULN.COUNT <component_digest>` → `:n`. Mirrors
    /// `qihse_ctrl_supply_vuln_count`.
    pub fn supply_vuln_count(&mut self, component_digest: &str) -> Result<Reply, ControllerError> {
        self.call_fed("SUPPLY.VULN.COUNT", &[component_digest])
    }

    // ── §31: Provenance graph ─────────────────────────────────────────

    /// `FEDERATION PROV.NODE <entity> <id> [label]` → `+OK`. Mirrors
    /// `qihse_ctrl_prov_node`.
    pub fn prov_node(
        &mut self,
        entity: &str,
        id: &str,
        label: Option<&str>,
    ) -> Result<Reply, ControllerError> {
        let mut args = vec![entity, id];
        if let Some(l) = label {
            args.push(l);
        }
        self.call_fed("PROV.NODE", &args)
    }

    /// `FEDERATION PROV.EDGE <from_ref> <edge> <to_ref>` → `+OK`. Mirrors
    /// `qihse_ctrl_prov_edge`.
    pub fn prov_edge(
        &mut self,
        from_ref: &str,
        edge: &str,
        to_ref: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed("PROV.EDGE", &[from_ref, edge, to_ref])
    }

    /// `FEDERATION PROV.SHOW <entity> <id>` → the record. Mirrors
    /// `qihse_ctrl_prov_show`.
    pub fn prov_show(&mut self, entity: &str, id: &str) -> Result<Reply, ControllerError> {
        self.call_fed("PROV.SHOW", &[entity, id])
    }

    /// `FEDERATION PROV.TRACE <entity> <id> <forward|reverse> [depth]` → the
    /// trace; `depth` 0 selects the server's default bound. Mirrors
    /// `qihse_ctrl_prov_trace`.
    pub fn prov_trace(
        &mut self,
        entity: &str,
        id: &str,
        forward: bool,
        depth: u32,
    ) -> Result<Reply, ControllerError> {
        let dir = if forward { "forward" } else { "reverse" };
        let d = depth.to_string();
        let args = if depth == 0 {
            vec![entity, id, dir]
        } else {
            vec![entity, id, dir, d.as_str()]
        };
        self.call_fed("PROV.TRACE", &args)
    }

    /// `FEDERATION PROV.IMPACT <entity> <id> <want_entity> [depth]` → the
    /// impact set. Mirrors `qihse_ctrl_prov_impact`.
    pub fn prov_impact(
        &mut self,
        entity: &str,
        id: &str,
        want_entity: &str,
        depth: u32,
    ) -> Result<Reply, ControllerError> {
        let d = depth.to_string();
        let args = if depth == 0 {
            vec![entity, id, want_entity]
        } else {
            vec![entity, id, want_entity, d.as_str()]
        };
        self.call_fed("PROV.IMPACT", &args)
    }

    // ── §23/§24/§36–§38: Operational admin ────────────────────────────

    /// `FEDERATION SNAPSHOT.CREATE <kind> <max_generation> <wal_offset>
    /// [key_id]` → the snapshot id; `kind` is `"local"` or `"coordinated"`,
    /// `key_id` `None` = unencrypted manifest. Mirrors
    /// `qihse_ctrl_snapshot_create`.
    pub fn snapshot_create(
        &mut self,
        kind: &str,
        max_generation: u64,
        wal_offset: u64,
        key_id: Option<&str>,
    ) -> Result<Reply, ControllerError> {
        let (gen, wal) = (max_generation.to_string(), wal_offset.to_string());
        let mut args = vec![kind, gen.as_str(), wal.as_str()];
        if let Some(k) = key_id {
            args.push(k);
        }
        self.call_fed("SNAPSHOT.CREATE", &args)
    }

    /// `FEDERATION SNAPSHOT.SHOW <snapshot_id>` → the record. Mirrors
    /// `qihse_ctrl_snapshot_show`.
    pub fn snapshot_show(&mut self, snapshot_id: &str) -> Result<Reply, ControllerError> {
        self.call_fed("SNAPSHOT.SHOW", &[snapshot_id])
    }

    /// `FEDERATION SNAPSHOT.VERIFY <snapshot_id>` → the verdict. Mirrors
    /// `qihse_ctrl_snapshot_verify`.
    pub fn snapshot_verify(&mut self, snapshot_id: &str) -> Result<Reply, ControllerError> {
        self.call_fed("SNAPSHOT.VERIFY", &[snapshot_id])
    }

    /// `FEDERATION SCHEMA.STATUS <schema_id> <version>` → status record.
    /// Mirrors `qihse_ctrl_schema_status`.
    pub fn schema_status(
        &mut self,
        schema_id: &str,
        version: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed("SCHEMA.STATUS", &[schema_id, version])
    }

    /// `FEDERATION SCHEMA.CHECK <writer_version> <min_reader>
    /// <required_hex> <optional_hex>` → compat verdict. Mirrors
    /// `qihse_ctrl_schema_check`.
    pub fn schema_check(
        &mut self,
        writer_version: &str,
        min_reader: &str,
        required_hex: &str,
        optional_hex: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed(
            "SCHEMA.CHECK",
            &[writer_version, min_reader, required_hex, optional_hex],
        )
    }

    /// `FEDERATION SCHEMA.MIGRATE <schema_id> <from> <to> <1|0>` → `+OK`;
    /// the flag marks the migration resumable. Mirrors
    /// `qihse_ctrl_schema_migrate`.
    pub fn schema_migrate(
        &mut self,
        schema_id: &str,
        from_version: &str,
        to_version: &str,
        resumable: bool,
    ) -> Result<Reply, ControllerError> {
        self.call_fed(
            "SCHEMA.MIGRATE",
            &[schema_id, from_version, to_version, if resumable { "1" } else { "0" }],
        )
    }

    /// `FEDERATION SCHEMA.PROGRESS <schema_id> <version> <completed>
    /// <total>` → the progress record. Mirrors `qihse_ctrl_schema_progress`.
    pub fn schema_progress(
        &mut self,
        schema_id: &str,
        version: &str,
        completed: u64,
        total: u64,
    ) -> Result<Reply, ControllerError> {
        let (done, all) = (completed.to_string(), total.to_string());
        self.call_fed(
            "SCHEMA.PROGRESS",
            &[schema_id, version, done.as_str(), all.as_str()],
        )
    }

    // ── §39: Security posture ─────────────────────────────────────────

    /// `FEDERATION SECURITY.AUDIT [service] [version]` → the runtime
    /// self-audit report. Mirrors `qihse_ctrl_security_audit`.
    pub fn security_audit(
        &mut self,
        service: Option<&str>,
        version: Option<&str>,
    ) -> Result<Reply, ControllerError> {
        let mut args = Vec::new();
        if let Some(s) = service {
            args.push(s);
        }
        if let Some(v) = version {
            args.push(v);
        }
        self.call_fed("SECURITY.AUDIT", &args)
    }

    /// `FEDERATION SECURITY.OBSERVE` → the node's runtime observation
    /// (uid/gid/caps/core-dump/seccomp/listeners). Mirrors
    /// `qihse_ctrl_security_observe`.
    pub fn security_observe(&mut self) -> Result<Reply, ControllerError> {
        self.call_fed("SECURITY.OBSERVE", &[])
    }

    /// `FEDERATION SECURITY.IFACES` → the kernel-interface classification.
    /// Mirrors `qihse_ctrl_security_ifaces`.
    pub fn security_ifaces(&mut self) -> Result<Reply, ControllerError> {
        self.call_fed("SECURITY.IFACES", &[])
    }

    /// `FEDERATION SECURITY.PROFILE.GET <service> <version>` → the declared
    /// runtime profile. Mirrors `qihse_ctrl_security_profile_get`.
    pub fn security_profile_get(
        &mut self,
        service: &str,
        version: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed("SECURITY.PROFILE.GET", &[service, version])
    }

    /// `FEDERATION SECURITY.NET.GET <service> <version>` → the declared
    /// network profile. Mirrors `qihse_ctrl_security_net_get`.
    pub fn security_net_get(
        &mut self,
        service: &str,
        version: &str,
    ) -> Result<Reply, ControllerError> {
        self.call_fed("SECURITY.NET.GET", &[service, version])
    }
}

// ============================================================================
// Object CAS preconditions
// ============================================================================

/// Explicit generation precondition for [`ControllerClient::object_cas`].
/// `expected_generation 0` means create-only on the wire, exactly as in the
/// C client — the enum makes the precondition impossible to mistake for a
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasPrecondition {
    /// Succeed only if the object does not exist yet (wire: `0`).
    CreateOnly,
    /// Succeed only if the object's current generation equals this value
    /// (wire: the value itself).
    IfGenerationIs(u64),
}

// ============================================================================
// Watches
// ============================================================================

/// One delivered journal event (`[offset, event_type, resource_id, payload]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    offset: u64,
    event_type: String,
    resource_id: String,
    payload: Vec<u8>,
}

impl WatchEvent {
    /// Journal offset of the event — the resumable cursor position.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Event type name (e.g. `"vm.created"`).
    pub fn event_type(&self) -> &str {
        &self.event_type
    }
    /// Resource id the event is about.
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
    /// Byte-exact event payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Consume the event, yielding the payload bytes.
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// A stateful, resumable watch over the event journal.
///
/// The cursor pair gives at-least-once delivery across reconnects:
/// [`Watch::next`] advances `delivered`; [`Watch::ack`] advances `acked` on
/// the server; [`Watch::reopen`] re-opens the session watch and rewinds it to
/// the last **acked** cursor, so events that were delivered but not acked are
/// redelivered and nothing acked is lost.
///
/// The watch never touches the network on its own — every method borrows the
/// [`ControllerClient`] to use for the round-trip.
#[derive(Debug, Clone)]
pub struct Watch {
    id: u32,
    prefix: Option<String>,
    acked: u64,
    delivered: u64,
}

impl Watch {
    /// Server-assigned watch id (session-scoped).
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The resource-id prefix filter this watch was opened with.
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    /// Highest journal offset handed to the caller by [`Watch::next`].
    pub fn delivered_cursor(&self) -> u64 {
        self.delivered
    }

    /// Highest journal offset the server has been told (via [`Watch::ack`])
    /// it may drop. [`Watch::reopen`] resumes from here.
    pub fn acked_cursor(&self) -> u64 {
        self.acked
    }

    /// Deliver the next event, or `None` at journal end. Updates
    /// [`Watch::delivered_cursor`] on delivery.
    pub fn next(
        &mut self,
        client: &mut ControllerClient,
    ) -> Result<Option<WatchEvent>, ControllerError> {
        let event = client.watch_next(self.id)?;
        if let Some(ev) = &event {
            self.delivered = self.delivered.max(ev.offset);
        }
        Ok(event)
    }

    /// Acknowledge everything up to [`Watch::delivered_cursor`] (`WATCH.ACK`)
    /// and advance the acked cursor to match.
    pub fn ack(&mut self, client: &mut ControllerClient) -> Result<(), ControllerError> {
        client.watch_ack(self.id, self.delivered)?;
        self.acked = self.delivered;
        Ok(())
    }

    /// Rewind the watch to `cursor` (`WATCH.RESUME`); both cursors follow so
    /// a second pass re-delivers from there.
    pub fn resume(
        &mut self,
        client: &mut ControllerClient,
        cursor: u64,
    ) -> Result<(), ControllerError> {
        client.watch_resume(self.id, cursor)?;
        self.acked = cursor;
        self.delivered = cursor;
        Ok(())
    }

    /// Re-open the watch after a reconnect: `WATCH.OPEN` with the same
    /// prefix, then `WATCH.RESUME` to the last acked cursor. Watch ids are
    /// session-scoped server state, so this is the required way to carry a
    /// watch across a new [`ControllerClient`].
    pub fn reopen(&mut self, client: &mut ControllerClient) -> Result<(), ControllerError> {
        let new_id = client.watch_open_id(self.prefix.as_deref())?;
        client.watch_resume(new_id, self.acked)?;
        self.id = new_id;
        Ok(())
    }
}

// ============================================================================
// Unit tests (decoder + encoder, on in-memory input)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &[u8]) -> Result<Reply, ControllerError> {
        let mut wire = Wire::new(input);
        parse_reply(&mut wire, 0)
    }

    #[test]
    fn simple_and_int_replies() {
        assert_eq!(parse(b"+OK\r\n").unwrap(), Reply::Simple("OK".into()));
        assert_eq!(parse(b"+QUEUED\r\n").unwrap(), Reply::Simple("QUEUED".into()));
        assert_eq!(parse(b":42\r\n").unwrap(), Reply::Int(42));
        assert_eq!(parse(b":-7\r\n").unwrap(), Reply::Int(-7));
        assert_eq!(parse(b":0\r\n").unwrap(), Reply::Int(0));
    }

    #[test]
    fn nil_replies() {
        assert_eq!(parse(b"$-1\r\n").unwrap(), Reply::Nil);
        assert_eq!(parse(b"*-1\r\n").unwrap(), Reply::Nil);
    }

    #[test]
    fn bulk_payload_is_byte_exact() {
        // Payload containing CRLF and NUL bytes — must not be interpreted.
        let wire = b"$12\r\nbin\x00\r\ndata!!\r\n";
        let parsed = parse(wire).unwrap();
        match parsed {
            Reply::Bulk(b) => assert_eq!(b, b"bin\x00\r\ndata!!"),
            other => panic!("expected bulk, got {other:?}"),
        }
    }

    #[test]
    fn empty_bulk_and_array() {
        assert_eq!(parse(b"$0\r\n\r\n").unwrap(), Reply::Bulk(vec![]));
        assert_eq!(parse(b"*0\r\n").unwrap(), Reply::Array(vec![]));
    }

    #[test]
    fn nested_array_parses() {
        let wire = b"*2\r\n$6\r\nnode-1\r\n*2\r\n:7\r\n$8\r\nattested\r\n";
        let parsed = parse(wire).unwrap();
        let items = parsed.as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_bytes(), Some(&b"node-1"[..]));
        let inner = items[1].as_array().unwrap();
        assert_eq!(inner[0].as_i64(), Some(7));
        assert_eq!(inner[1].as_str(), Some("attested"));
    }

    #[test]
    fn oversized_bulk_is_rejected_as_error() {
        let err = parse(format!("${}\r\n", MAX_BULK + 1).as_bytes()).unwrap_err();
        match err {
            ControllerError::OversizedBulk { declared } => {
                assert_eq!(declared, MAX_BULK + 1);
            }
            other => panic!("expected OversizedBulk, got {other:?}"),
        }
    }

    #[test]
    fn max_bulk_boundary_is_accepted() {
        let mut wire = format!("${}\r\n", MAX_BULK).into_bytes();
        wire.extend(std::iter::repeat(b'x').take(MAX_BULK));
        wire.extend_from_slice(b"\r\n");
        match parse(&wire).unwrap() {
            Reply::Bulk(b) => {
                assert_eq!(b.len(), MAX_BULK);
                assert_eq!(b[0], b'x');
                assert_eq!(b[MAX_BULK - 1], b'x');
            }
            other => panic!("expected bulk, got {other:?}"),
        }
    }

    #[test]
    fn too_many_items_is_rejected_as_error() {
        let err = parse(format!("*{}\r\n", MAX_ITEMS + 1).as_bytes()).unwrap_err();
        match err {
            ControllerError::TooManyItems { declared } => {
                assert_eq!(declared, (MAX_ITEMS + 1) as i64);
            }
            other => panic!("expected TooManyItems, got {other:?}"),
        }
    }

    #[test]
    fn items_boundary_count_is_not_rejected_up_front() {
        // Exactly MAX_ITEMS declared items is within the cap; with no items
        // following, the decoder fails on EOF (Closed), not on the cap.
        let err = parse(format!("*{}\r\n", MAX_ITEMS).as_bytes()).unwrap_err();
        assert!(matches!(err, ControllerError::Closed));
    }

    #[test]
    fn too_deep_is_rejected_as_error() {
        // 33 nested array headers: the parser enters depth 33 > MAX_DEPTH.
        let mut wire = Vec::new();
        for _ in 0..MAX_DEPTH + 1 {
            wire.extend_from_slice(b"*1\r\n");
        }
        let err = parse(&wire).unwrap_err();
        match err {
            ControllerError::TooDeep { depth } => assert_eq!(depth, MAX_DEPTH + 1),
            other => panic!("expected TooDeep, got {other:?}"),
        }
    }

    #[test]
    fn depth_boundary_is_accepted() {
        // 32 nested arrays plus a leaf: deepest legal reply.
        let mut wire = Vec::new();
        for _ in 0..MAX_DEPTH {
            wire.extend_from_slice(b"*1\r\n");
        }
        wire.extend_from_slice(b"+leaf\r\n");
        let mut expected = Reply::Simple("leaf".into());
        for _ in 0..MAX_DEPTH {
            expected = Reply::Array(vec![expected]);
        }
        assert_eq!(parse(&wire).unwrap(), expected);
    }

    #[test]
    fn malformed_replies_are_protocol_errors() {
        assert!(matches!(
            parse(b":12x\r\n").unwrap_err(),
            ControllerError::Protocol(_)
        ));
        assert!(matches!(
            parse(b": 5\r\n").unwrap_err(),
            ControllerError::Protocol(_)
        ));
        assert!(matches!(
            parse(b"!bang\r\n").unwrap_err(),
            ControllerError::Protocol(_)
        ));
        assert!(matches!(
            parse(b"\r\n").unwrap_err(),
            ControllerError::Protocol(_)
        ));
        // Overlong line (>= 128 bytes without CRLF).
        let long: Vec<u8> = std::iter::once(b'+')
            .chain(std::iter::repeat(b'A').take(200))
            .collect();
        assert!(matches!(
            parse(&long).unwrap_err(),
            ControllerError::Protocol(_)
        ));
    }

    #[test]
    fn truncated_input_reports_closed() {
        assert!(matches!(parse(b"").unwrap_err(), ControllerError::Closed));
        assert!(matches!(parse(b"$3\r\nab").unwrap_err(), ControllerError::Closed));
        assert!(matches!(parse(b"$3").unwrap_err(), ControllerError::Closed));
    }

    #[test]
    fn missing_crlf_after_bulk_is_protocol_error() {
        let err = parse(b"$3\r\nabcXY").unwrap_err();
        assert!(matches!(err, ControllerError::Protocol(_)));
    }

    #[test]
    fn error_class_and_message_split() {
        assert_eq!(
            split_error("NOPERM caller lacks clearance for vm-1"),
            ("NOPERM".to_string(), "caller lacks clearance for vm-1".to_string())
        );
        assert_eq!(split_error("ERR"), ("ERR".to_string(), String::new()));
        let parsed = parse(b"-NOPERM denied\r\n").unwrap();
        assert_eq!(
            parsed,
            Reply::Error {
                class: "NOPERM".into(),
                message: "denied".into()
            }
        );
    }

    #[test]
    fn command_encoding_is_exact() {
        let frame = encode_command(&[b"FEDERATION", b"NODE.LIST"]).unwrap();
        assert_eq!(frame, b"*2\r\n$10\r\nFEDERATION\r\n$9\r\nNODE.LIST\r\n");
        let frame = encode_command(&[b""]).unwrap();
        assert_eq!(frame, b"*1\r\n$0\r\n\r\n");
        let frame = encode_command(&[b"A\r\nB\x00"]).unwrap();
        assert_eq!(frame, b"*1\r\n$5\r\nA\r\nB\x00\r\n");
    }

    #[test]
    fn oversized_command_is_rejected_before_encoding() {
        let huge = vec![b'x'; MAX_BULK];
        let err = encode_command(&[&huge]).unwrap_err();
        match err {
            ControllerError::CommandTooLarge { bytes } => assert!(bytes > MAX_BULK),
            other => panic!("expected CommandTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn u64_formatting_covers_boundaries() {
        let mut buf = Vec::new();
        push_u64(&mut buf, 0);
        push_u64(&mut buf, u64::MAX);
        assert_eq!(buf, b"018446744073709551615");
    }

    #[test]
    fn error_display_includes_class_and_message() {
        let e = ControllerError::Server {
            class: "NOPERM".into(),
            message: "clearance below object".into(),
        };
        let text = e.to_string();
        assert!(text.contains("NOPERM") && text.contains("clearance below object"));
    }
}
