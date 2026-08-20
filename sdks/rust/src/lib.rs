//! QIHSE Rust SDK - Multi-protocol database SDK
//!
//! Compatible with tokio-postgres, pymongo, mongoc, requests, clickhouse-driver,
//! elasticsearch-py, prometheus-client, and opentelemetry APIs.

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

// MongoDB wire protocol
pub use mongo::{Client as MongoClient, Database as MongoDatabase, Collection as MongoCollection,
                Document as MongoDocument, BsonValue, Cursor as MongoCursor, MongoError};

// HTTP/REST
pub use http::{HttpClient, Response as HttpResponse, Method as HttpMethod, HttpError};

// CDC
pub use cdc::{CdcClient, CdcEvent, CdcOp, CdcCallback};

// Metrics & Tracing
pub use metrics::{Counter, Gauge, Histogram, CollectorRegistry, Span, Tracer};
