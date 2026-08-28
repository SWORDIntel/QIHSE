//! QIHSE Rust SDK - Multi-protocol database SDK
//!
//! Compatible with tokio-postgres, pymongo, mongoc, requests, clickhouse-driver,
//! elasticsearch-py, prometheus-client, and opentelemetry APIs.
//!
//! Audited for UWP wire-level safety: error handling, auth enforcement,
//! frame reassembly, version validation.
//!
//! Audit findings:
//! - The SDK was a stub: all query methods returned empty results without
//!   any wire interaction.  No UWP protocol, auth, or error handling existed.
//! - Added `error` module with UwpError enum, UwpHeader/UwpFrame structs,
//!   and AuthState for auth-gate enforcement.
//! - The client methods remain stubs (they do not yet speak UWP over the
//!   wire), but the type infrastructure is in place for a future
//!   implementation.  See the `error` module for the full protocol types.

pub mod error;
pub mod client;
pub mod query;
pub mod types;
pub mod mongo;
pub mod http;
pub mod cdc;
pub mod metrics;

pub use client::{Client, Config, Connection, Transaction, NoTls};
pub use query::{Row, RowIter, SimpleQueryRow, SimpleQueryMessage};
pub use types::Type;
pub use tokio_postgres::error::Error;

// UWP wire protocol types (audited)
pub use error::{UwpError, UwpHeader, UwpFrame, AuthState, parse_response,
                UWP_MAGIC, UWP_VERSION, UWP_HEADER_SIZE, UWP_MAX_PAYLOAD,
                AUTH_CMD, target};

// MongoDB wire protocol
pub use mongo::{Client as MongoClient, Database as MongoDatabase, Collection as MongoCollection,
                Document as MongoDocument, BsonValue, Cursor as MongoCursor, MongoError};

// HTTP/REST
pub use http::{HttpClient, Response as HttpResponse, Method as HttpMethod, HttpError};

// CDC
pub use cdc::{CdcClient, CdcEvent, CdcOp, CdcCallback};

// Metrics & Tracing
pub use metrics::{Counter, Gauge, Histogram, CollectorRegistry, Span, Tracer};
