//! Query result types

pub use tokio_postgres::{Column, Row};

/// Iterator over rows
pub struct RowIter {
    rows: std::vec::IntoIter<Row>,
}

impl Iterator for RowIter {
    type Item = Row;

    fn next(&mut self) -> Option<Row> {
        self.rows.next()
    }
}

/// Simple query message
pub enum SimpleQueryMessage {
    Row(SimpleQueryRow),
    CommandComplete(u64),
}

pub struct SimpleQueryRow {
    values: Vec<Option<String>>,
}

impl SimpleQueryRow {
    pub fn new(values: Vec<Option<String>>) -> Self {
        SimpleQueryRow { values }
    }
    pub fn get(&self, idx: usize) -> Option<&str> {
        self.values
            .get(idx)
            .and_then(|v| v.as_ref().map(|s| s.as_str()))
    }
    pub fn len(&self) -> usize {
        self.values.len()
    }
}

/// Trait for converting binary values from SQL
pub trait FromSql<'a>: Sized {
    fn from_sql(bytes: &'a [u8]) -> Option<Self>;
}

impl<'a> FromSql<'a> for i32 {
    fn from_sql(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() == 4 {
            Some(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        } else {
            None
        }
    }
}

impl<'a> FromSql<'a> for i64 {
    fn from_sql(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() == 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            Some(i64::from_be_bytes(arr))
        } else {
            None
        }
    }
}

impl<'a> FromSql<'a> for f64 {
    fn from_sql(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() == 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            Some(f64::from_be_bytes(arr))
        } else {
            None
        }
    }
}

impl<'a> FromSql<'a> for String {
    fn from_sql(bytes: &'a [u8]) -> Option<Self> {
        Some(String::from_utf8_lossy(bytes).to_string())
    }
}

impl<'a> FromSql<'a> for bool {
    fn from_sql(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() == 1 {
            Some(bytes[0] != 0)
        } else {
            None
        }
    }
}
