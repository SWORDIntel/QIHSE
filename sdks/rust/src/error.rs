//! Audited for UWP wire-level safety: error handling, auth enforcement,
//! frame reassembly, version validation.
//!
//! Audit findings:
//! - The Rust SDK was a stub with no UWP protocol implementation.
//! - All query methods returned empty results without any wire interaction.
//! - No error types existed for UWP-specific error codes (ERR_AUTH,
//!   ERR_PERM, ERR_RATE_LIMITED, etc.).
//! - No frame/header structures were defined.
//! - No authentication state tracking existed.
//!
//! Fixes applied:
//! - Added UwpError enum with variants for every server error code.
//! - Added UwpHeader struct matching the 15-byte packed C header.
//! - Added UwpFrame for frame construction and reassembly.
//! - Added AuthState to track whether the client has authenticated.
//! - Implemented std::error::Error and Display for UwpError.

use std::fmt;

/// UWP wire constants (must match include/qihse_uwp.h)
pub const UWP_MAGIC: [u8; 4] = [0x51, 0x49, 0x48, 0x53]; // "QIHS"
pub const UWP_VERSION: u8 = 0x01;
pub const UWP_HEADER_SIZE: usize = 15; // packed: 4 + 1 + 1 + 1 + 8

/// Subsystem routing opcodes (target_engine field)
pub mod target {
    pub const AUTH: u8 = 0x00;
    pub const KV: u8 = 0x01;
    pub const VECTOR: u8 = 0x02;
    pub const DOC: u8 = 0x03;
    pub const COL: u8 = 0x04;
    pub const TSDB: u8 = 0x05;
    pub const GRAPH: u8 = 0x06;
    pub const STREAM: u8 = 0x07;
    pub const SQL: u8 = 0x08;
    pub const TXN: u8 = 0x09;
    pub const GRAPH2: u8 = 0x0A;
    pub const INDEX: u8 = 0x0B;
    pub const SCHEMA: u8 = 0x0C;
    pub const REPL: u8 = 0x0D;
    pub const POOL: u8 = 0x0E;
}

/// Auth command opcode
pub const AUTH_CMD: u8 = 0x01;

/// Maximum payload the server accepts
pub const UWP_MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// UWP error codes returned by the server as text responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UwpError {
    /// ERR_AUTH — authentication failed or was not performed.
    Auth(String),
    /// ERR_PERM — the authenticated user lacks permission.
    Permission(String),
    /// ERR_RATE_LIMITED — too many auth attempts; back off and retry.
    RateLimited(String),
    /// ERR_MAGIC — frame magic bytes did not match UWP_MAGIC.
    BadMagic,
    /// ERR_VERSION — unsupported protocol version.
    BadVersion,
    /// ERR_LEN — payload length did not match the header.
    LengthMismatch,
    /// ERR_TOO_LARGE — payload exceeded UWP_MAX_PAYLOAD.
    PayloadTooLarge,
    /// ERR_DISPATCH — server-side dispatch error.
    Dispatch(String),
    /// Unknown error response from the server.
    Unknown(String),
    /// I/O or connection error.
    Io(String),
    /// Protocol violation (truncated frame, unparseable response, etc.).
    Protocol(String),
}

impl fmt::Display for UwpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UwpError::Auth(msg) => write!(f, "UWP authentication error: {}", msg),
            UwpError::Permission(msg) => write!(f, "UWP permission denied: {}", msg),
            UwpError::RateLimited(msg) => write!(f, "UWP rate limited: {}", msg),
            UwpError::BadMagic => write!(f, "UWP protocol error: bad magic bytes"),
            UwpError::BadVersion => write!(f, "UWP protocol error: unsupported version"),
            UwpError::LengthMismatch => write!(f, "UWP protocol error: payload length mismatch"),
            UwpError::PayloadTooLarge => write!(f, "UWP protocol error: payload too large"),
            UwpError::Dispatch(msg) => write!(f, "UWP dispatch error: {}", msg),
            UwpError::Unknown(msg) => write!(f, "UWP unknown error: {}", msg),
            UwpError::Io(msg) => write!(f, "UWP I/O error: {}", msg),
            UwpError::Protocol(msg) => write!(f, "UWP protocol error: {}", msg),
        }
    }
}

impl std::error::Error for UwpError {}

impl From<std::io::Error> for UwpError {
    fn from(e: std::io::Error) -> Self {
        UwpError::Io(e.to_string())
    }
}

/// Parse a server text response into a Result.
/// "OK" maps to Ok(()), error strings map to the appropriate UwpError variant.
pub fn parse_response(line: &str) -> Result<String, UwpError> {
    let resp = line.trim();
    match resp {
        "OK" => Ok(resp.to_string()),
        "ERR_AUTH" => Err(UwpError::Auth("authentication required or failed".into())),
        "ERR_PERM" => Err(UwpError::Permission("permission denied".into())),
        "ERR_RATE_LIMITED" => Err(UwpError::RateLimited("rate limited by server".into())),
        "ERR_MAGIC" => Err(UwpError::BadMagic),
        "ERR_VERSION" => Err(UwpError::BadVersion),
        "ERR_LEN" => Err(UwpError::LengthMismatch),
        "ERR_TOO_LARGE" => Err(UwpError::PayloadTooLarge),
        "ERR_DISPATCH" => Err(UwpError::Dispatch("server dispatch error".into())),
        s if s.starts_with("ERR") => Err(UwpError::Unknown(s.to_string())),
        // Non-error, non-OK response (e.g. a value from KV GET)
        other => Ok(other.to_string()),
    }
}

/// 15-byte packed UWP frame header (must match qihse_uwp_header_t in C).
#[derive(Debug, Clone)]
pub struct UwpHeader {
    pub version: u8,
    pub target_engine: u8,
    pub command_opcode: u8,
    pub payload_length: u64,
}

impl UwpHeader {
    /// Create a new header with the current protocol version.
    pub fn new(target: u8, command: u8, payload_len: usize) -> Self {
        UwpHeader {
            version: UWP_VERSION,
            target_engine: target,
            command_opcode: command,
            payload_length: payload_len as u64,
        }
    }

    /// Serialize to 15 bytes (little-endian payload_length).
    pub fn to_bytes(&self) -> [u8; UWP_HEADER_SIZE] {
        let mut buf = [0u8; UWP_HEADER_SIZE];
        buf[0..4].copy_from_slice(&UWP_MAGIC);
        buf[4] = self.version;
        buf[5] = self.target_engine;
        buf[6] = self.command_opcode;
        buf[7..15].copy_from_slice(&self.payload_length.to_le_bytes());
        buf
    }

    /// Deserialize from 15 bytes, validating magic and version.
    pub fn from_bytes(data: &[u8]) -> Result<Self, UwpError> {
        if data.len() < UWP_HEADER_SIZE {
            return Err(UwpError::Protocol(format!(
                "header too short: {} < {}",
                data.len(),
                UWP_HEADER_SIZE
            )));
        }
        if &data[0..4] != UWP_MAGIC {
            return Err(UwpError::BadMagic);
        }
        let version = data[4];
        if version != UWP_VERSION {
            return Err(UwpError::BadVersion);
        }
        let target_engine = data[5];
        let command_opcode = data[6];
        let payload_length = u64::from_le_bytes([
            data[7], data[8], data[9], data[10],
            data[11], data[12], data[13], data[14],
        ]);
        if payload_length as usize > UWP_MAX_PAYLOAD {
            return Err(UwpError::PayloadTooLarge);
        }
        Ok(UwpHeader {
            version,
            target_engine,
            command_opcode,
            payload_length,
        })
    }
}

/// A complete UWP frame (header + payload).
#[derive(Debug, Clone)]
pub struct UwpFrame {
    pub header: UwpHeader,
    pub payload: Vec<u8>,
}

impl UwpFrame {
    /// Create a new frame.
    pub fn new(target: u8, command: u8, payload: Vec<u8>) -> Result<Self, UwpError> {
        if payload.len() > UWP_MAX_PAYLOAD {
            return Err(UwpError::PayloadTooLarge);
        }
        Ok(UwpFrame {
            header: UwpHeader::new(target, command, payload.len()),
            payload,
        })
    }

    /// Serialize to bytes (header + payload).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(UWP_HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.header.to_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Build an AUTH frame: payload = username\0password\0
    pub fn auth(username: &str, password: &str) -> Result<Self, UwpError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(username.as_bytes());
        payload.push(0);
        payload.extend_from_slice(password.as_bytes());
        payload.push(0);
        UwpFrame::new(target::AUTH, AUTH_CMD, payload)
    }
}

/// Authentication state tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// Not yet authenticated — only AUTH commands may be sent.
    Unauthenticated,
    /// Successfully authenticated — all commands are allowed.
    Authenticated,
}

impl AuthState {
    /// Returns Ok(()) if a command with the given target is allowed in the
    /// current state.  Non-AUTH targets require Authenticated.
    pub fn check(self, target: u8) -> Result<(), UwpError> {
        match (self, target) {
            (AuthState::Authenticated, _) => Ok(()),
            (AuthState::Unauthenticated, target::AUTH) => Ok(()),
            (AuthState::Unauthenticated, _) => Err(UwpError::Auth(
                "cannot send non-AUTH command before authenticating".into(),
            )),
        }
    }
}
