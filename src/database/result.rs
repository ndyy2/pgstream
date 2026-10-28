//! Result data structure for executed queries.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct QueryResult {
    pub rows_affected: u64,
    pub columns: Vec<String>,
    pub col_indices: HashMap<String, usize>,
    pub rows: Vec<Vec<Option<String>>>,
    pub error: Option<String>,
}

impl QueryResult {
    pub fn new(columns: Vec<String>, rows: Vec<Vec<Option<String>>>, rows_affected: u64) -> Self {
        let mut col_indices = HashMap::new();
        for (idx, name) in columns.iter().enumerate() {
            col_indices.insert(name.to_lowercase(), idx);
        }
        Self {
            rows_affected,
            columns,
            col_indices,
            rows,
            error: None,
        }
    }

    pub fn empty_success(rows_affected: u64) -> Self {
        Self {
            rows_affected,
            columns: Vec::new(),
            col_indices: HashMap::new(),
            rows: Vec::new(),
            error: None,
        }
    }

    pub fn error(err: String) -> Self {
        Self {
            rows_affected: 0,
            columns: Vec::new(),
            col_indices: HashMap::new(),
            rows: Vec::new(),
            error: Some(err),
        }
    }

    pub fn get_col_index(&self, name: &str) -> Option<usize> {
        self.col_indices.get(&name.to_lowercase()).copied()
    }

    pub fn is_null(&self, row: usize, col: usize) -> bool {
        match self.rows.get(row).and_then(|r| r.get(col)) {
            Some(val) => val.is_none(),
            None => true, // Out of bounds is treated as null
        }
    }

    pub fn get_value(&self, row: usize, col: usize) -> Option<&str> {
        self.rows
            .get(row)
            .and_then(|r| r.get(col))
            .and_then(|v| v.as_deref())
    }
}
