use bytes::BytesMut;
use std::error::Error;
use tokio_postgres::types::{to_sql_checked, IsNull, ToSql, Type};

#[derive(Debug, Clone, PartialEq)]
pub enum SqlParam {
    Int(i32),
    Float(f64),
    String(String),
    Bool(bool),
    Null,
}

impl ToSql for SqlParam {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        match self {
            SqlParam::Int(val) => (*val).to_sql(ty, out),
            SqlParam::Float(val) => (*val).to_sql(ty, out),
            SqlParam::String(val) => val.as_str().to_sql(ty, out),
            SqlParam::Bool(val) => (*val).to_sql(ty, out),
            SqlParam::Null => Ok(IsNull::Yes),
        }
    }

    fn accepts(_ty: &Type) -> bool {
        true
    }

    to_sql_checked!();
}
