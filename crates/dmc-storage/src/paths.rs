/// Default SQL database name mapped onto the single on-disk file.
pub const DEFAULT_DATABASE: &str = "main";
pub const DEFAULT_SCHEMA: &str = "public";
pub const SYSTEM_SCHEMA: &str = "system";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TableId {
    pub database: String,
    pub schema: String,
    pub name: String,
}

impl TableId {
    pub fn new(database: impl Into<String>, schema: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            database: database.into(),
            schema: schema.into(),
            name: name.into(),
        }
    }

    pub fn user(schema: &str, name: &str) -> Self {
        Self::new(DEFAULT_DATABASE, schema, name)
    }

    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.schema, self.name)
    }
}

/// Make a string safe as a single key-tree segment.
pub fn encode_segment(raw: &str) -> String {
    if raw.starts_with("h_")
        && raw.len() > 2
        && raw.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
    {
        return raw.to_string();
    }
    if raw.is_empty() || raw == "." || raw == ".." || raw.contains('/') || raw.contains('\0') {
        format!("h_{}", hex::encode(raw.as_bytes()))
    } else {
        raw.to_string()
    }
}

pub fn schema_key_path(database: &str, schema: &str) -> String {
    format!(
        "db/{}/schema/{}",
        encode_segment(database),
        encode_segment(schema)
    )
}

pub fn table_key_path(id: &TableId) -> String {
    format!(
        "{}/table/{}",
        schema_key_path(&id.database, &id.schema),
        encode_segment(&id.name)
    )
}

pub fn column_key_path(id: &TableId, column: &str) -> String {
    format!("{}/col/{}", table_key_path(id), encode_segment(column))
}

pub fn row_key_path(id: &TableId, row_id: &str) -> String {
    format!("{}/row/{}", table_key_path(id), encode_segment(row_id))
}

pub fn index_key_path(id: &TableId, index: &str) -> String {
    format!("{}/index/{}", table_key_path(id), encode_segment(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_paths_nest_columns_and_rows() {
        let t = TableId::user("public", "employees");
        assert_eq!(
            table_key_path(&t),
            "db/main/schema/public/table/employees"
        );
        assert_eq!(
            column_key_path(&t, "salary"),
            "db/main/schema/public/table/employees/col/salary"
        );
        assert_eq!(
            row_key_path(&t, "abc-1"),
            "db/main/schema/public/table/employees/row/abc-1"
        );
    }
}
