//! PostgreSQL type definitions

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Bool,
    Int2,
    Int4,
    Int8,
    Float4,
    Float8,
    Text,
    Varchar,
    Bytea,
    Json,
    Jsonb,
    Timestamp,
    TimestampTz,
    Date,
    Time,
    Uuid,
    Unknown,
}

impl Type {
    pub fn oid(&self) -> u32 {
        match self {
            Type::Bool => 16,
            Type::Bytea => 17,
            Type::Int2 => 21,
            Type::Int4 => 23,
            Type::Text => 25,
            Type::Int8 => 20,
            Type::Float4 => 700,
            Type::Float8 => 701,
            Type::Varchar => 1043,
            Type::Date => 1082,
            Type::Time => 1083,
            Type::Timestamp => 1114,
            Type::TimestampTz => 1184,
            Type::Uuid => 2950,
            Type::Json => 114,
            Type::Jsonb => 3802,
            Type::Unknown => 0,
        }
    }
    
    pub fn from_oid(oid: u32) -> Type {
        match oid {
            16 => Type::Bool,
            17 => Type::Bytea,
            21 => Type::Int2,
            23 => Type::Int4,
            25 => Type::Text,
            20 => Type::Int8,
            700 => Type::Float4,
            701 => Type::Float8,
            1043 => Type::Varchar,
            1082 => Type::Date,
            1083 => Type::Time,
            1114 => Type::Timestamp,
            1184 => Type::TimestampTz,
            2950 => Type::Uuid,
            114 => Type::Json,
            3802 => Type::Jsonb,
            _ => Type::Unknown,
        }
    }
}
