//! QIHSE Rust SDK - Multi-protocol database SDK
//!
//! Compatible with tokio-postgres, pymongo, mongoc, requests, clickhouse-driver,
//! elasticsearch-py, prometheus-client, and opentelemetry APIs.
//!
//! SQL calls use PostgreSQL wire protocol and authenticate through the
//! configured username/password during connection startup. UWP frame types
//! remain available independently for UWP protocol consumers.

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
