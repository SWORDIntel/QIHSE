//! Query result types

use std::collections::HashMap;
use crate::types::Type;

/// A row from a query result
pub struct Row {
    columns: Vec<Column>,
    values: Vec<Option<Vec<u8>>>,
}

pub struct Column {
    name: String,
    type_: Type,
}

impl Row {
    pub fn new(columns: Vec<Column>, values: Vec<Option<Vec<u8>>>) -> Self {
        Row { columns, values }
    }
    
    pub fn columns(&self) -> &[Column] { &self.columns }
    pub fn len(&self) -> usize { self.values.len() }
    pub fn is_empty(&self) -> bool { self.values.is_empty() }
    
    pub fn get<'a, I>(&'a self, idx: I) -> Option<&'a [u8]>
    where I: RowIndex
    {
        idx.idx(&self.columns).and_then(|i| self.values[i].as_ref().map(|v| v.as_slice()))
    }
    
    pub fn get_as<'a, I, T>(&'a self, idx: I) -> Option<T>
    where I: RowIndex, T: FromSql<'a>
    {
        self.get(idx).and_then(T::from_sql)
    }
    
    pub fn try_get<'a, I, T>(&'a self, idx: I) -> Result<T, Box<dyn std::error::Error>>
    where I: RowIndex, T: FromSql<'a>
    {
        // Simplified
        unimplemented!()
    }
}

pub trait RowIndex {
    fn idx(&self, columns: &[Column]) -> Option<usize>;
}

impl RowIndex for usize {
    fn idx(&self, columns: &[Column]) -> Option<usize> {
        if *self < columns.len() { Some(*self) } else { None }
    }
}

impl RowIndex for str {
    fn idx(&self, columns: &[Column]) -> Option<usize> {
        columns.iter().position(|c| c.name == self)
    }
}

impl<'a> RowIndex for &'a str {
    fn idx(&self, columns: &[Column]) -> Option<usize> {
        (*self).idx(columns)
    }
}

impl Column {
    pub fn new(name: String, type_: Type) -> Self { Column { name, type_ } }
    pub fn name(&self) -> &str { &self.name }
    pub fn type_(&self) -> &Type { &self.type_ }
}

/// Iterator over rows
pub struct RowIter {
    rows: Vec<Row>,
    idx: usize,
}

impl Iterator for RowIter {
    type Item = Row;
    
    fn next(&mut self) -> Option<Row> {
        if self.idx < self.rows.len() {
            let row = std::mem::replace(&mut self.rows[self.idx], Row::new(vec![], vec![]));
            self.idx += 1;
            Some(row)
        } else {
            None
        }
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
    pub fn new(values: Vec<Option<String>>) -> Self { SimpleQueryRow { values } }
    pub fn get(&self, idx: usize) -> Option<&str> {
        self.values.get(idx).and_then(|v| v.as_ref().map(|s| s.as_str()))
    }
    pub fn len(&self) -> usize { self.values.len() }
}

/// Trait for converting binary values from SQL
pub trait FromSql<'a>: Sized {
    fn from_sql(bytes: &'a [u8]) -> Option<Self>;
}

impl<'a> FromSql<'a> for i32 {
    fn from_sql(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() == 4 {
            Some(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        } else { None }
    }
}

impl<'a> FromSql<'a> for i64 {
    fn from_sql(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() == 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            Some(i64::from_be_bytes(arr))
        } else { None }
    }
}

impl<'a> FromSql<'a> for f64 {
    fn from_sql(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() == 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            Some(f64::from_be_bytes(arr))
        } else { None }
    }
}

impl<'a> FromSql<'a> for String {
    fn from_sql(bytes: &'a [u8]) -> Option<Self> {
        Some(String::from_utf8_lossy(bytes).to_string())
    }
}

impl<'a> FromSql<'a> for bool {
    fn from_sql(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() == 1 { Some(bytes[0] != 0) } else { None }
    }
}
