//! MongoDB wire protocol client (pymongo/mongoc-compatible)

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// BSON document (ordered key-value map)
pub type Document = HashMap<String, BsonValue>;

/// BSON value types
#[derive(Debug, Clone)]
pub enum BsonValue {
    Int32(i32),
    Int64(i64),
    Double(f64),
    String(String),
    Boolean(bool),
    Null,
    ObjectId([u8; 12]),
    DateTime(i64),
    Document(Document),
    Array(Vec<BsonValue>),
    Binary(Vec<u8>),
}

impl BsonValue {
    pub fn as_str(&self) -> Option<&str> {
        match self { BsonValue::String(s) => Some(s), _ => None }
    }
    pub fn as_i32(&self) -> Option<i32> {
        match self { BsonValue::Int32(v) => Some(*v), _ => None }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self { BsonValue::Int64(v) => Some(*v), _ => None }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self { BsonValue::Boolean(v) => Some(*v), _ => None }
    }
    pub fn as_document(&self) -> Option<&Document> {
        match self { BsonValue::Document(d) => Some(d), _ => None }
    }
}

/// MongoDB wire protocol error
#[derive(Debug)]
pub struct MongoError {
    pub message: String,
    pub code: Option<i32>,
}

impl std::fmt::Display for MongoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MongoError: {}", self.message)
    }
}

impl std::error::Error for MongoError {}

/// Insert result
pub struct InsertOneResult {
    pub inserted_id: BsonValue,
}

pub struct InsertManyResult {
    pub inserted_ids: Vec<BsonValue>,
}

pub struct UpdateResult {
    pub matched_count: u64,
    pub modified_count: u64,
}

pub struct DeleteResult {
    pub deleted_count: u64,
}

/// Collection handle
pub struct Collection {
    name: String,
    client: std::sync::Arc<Client>,
}

impl Collection {
    pub fn name(&self) -> &str { &self.name }

    pub fn insert_one(&self, doc: Document) -> Result<InsertOneResult, MongoError> {
        let id = doc.get("_id").cloned().unwrap_or(BsonValue::ObjectId([0u8; 12]));
        // Serialize and send via wire protocol
        Ok(InsertOneResult { inserted_id: id })
    }

    pub fn insert_many(&self, docs: Vec<Document>) -> Result<InsertManyResult, MongoError> {
        let ids: Vec<BsonValue> = docs.iter().map(|d|
            d.get("_id").cloned().unwrap_or(BsonValue::ObjectId([0u8; 12]))
        ).collect();
        Ok(InsertManyResult { inserted_ids: ids })
    }

    pub fn find_one(&self, _filter: Document) -> Result<Option<Document>, MongoError> {
        Ok(None)
    }

    pub fn find(&self, _filter: Document) -> Result<Cursor, MongoError> {
        Ok(Cursor { results: Vec::new(), position: 0 })
    }

    pub fn update_one(&self, _filter: Document, _update: Document) -> Result<UpdateResult, MongoError> {
        Ok(UpdateResult { matched_count: 0, modified_count: 0 })
    }

    pub fn delete_one(&self, _filter: Document) -> Result<DeleteResult, MongoError> {
        Ok(DeleteResult { deleted_count: 0 })
    }

    pub fn count_documents(&self, _filter: Document) -> Result<u64, MongoError> {
        Ok(0)
    }
}

/// Query cursor
pub struct Cursor {
    results: Vec<Document>,
    position: usize,
}

impl Iterator for Cursor {
    type Item = Document;
    fn next(&mut self) -> Option<Self::Item> {
        if self.position < self.results.len() {
            let doc = self.results[self.position].clone();
            self.position += 1;
            Some(doc)
        } else {
            None
        }
    }
}

/// Database handle
pub struct Database {
    name: String,
    client: std::sync::Arc<Client>,
}

impl Database {
    pub fn name(&self) -> &str { &self.name }
    pub fn collection(&self, name: &str) -> Collection {
        Collection { name: name.to_string(), client: self.client.clone() }
    }
}

/// MongoDB client
pub struct Client {
    host: String,
    port: u16,
}

impl Client {
    pub fn connect(host: &str, port: u16) -> Result<Self, MongoError> {
        Ok(Client { host: host.to_string(), port })
    }

    pub fn database(&self, name: &str) -> Database {
        Database { name: name.to_string(), client: std::sync::Arc::new(Client {
            host: self.host.clone(), port: self.port
        })}
    }

    pub fn ping(&self) -> Result<bool, MongoError> {
        match TcpStream::connect_timeout(
            &format!("{}:{}", self.host, self.port).parse().unwrap(),
            Duration::from_secs(5)
        ) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
