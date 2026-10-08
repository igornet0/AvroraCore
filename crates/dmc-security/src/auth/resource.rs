use std::fmt;

use serde::{Deserialize, Serialize};

/// Hierarchical catalog resource for SQL authorization.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Resource {
    System,
    Database { name: String },
    Schema { database: String, name: String },
    Table {
        database: String,
        schema: String,
        name: String,
    },
}

impl Resource {
    pub fn database(name: impl Into<String>) -> Self {
        Self::Database {
            name: name.into(),
        }
    }

    pub fn schema(database: impl Into<String>, name: impl Into<String>) -> Self {
        Self::Schema {
            database: database.into(),
            name: name.into(),
        }
    }

    pub fn table(
        database: impl Into<String>,
        schema: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self::Table {
            database: database.into(),
            schema: schema.into(),
            name: name.into(),
        }
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => write!(f, "system"),
            Self::Database { name } => write!(f, "database:{name}"),
            Self::Schema { database, name } => write!(f, "schema:{database}.{name}"),
            Self::Table {
                database,
                schema,
                name,
            } => write!(f, "table:{database}.{schema}.{name}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Connect,
    Usage,
    Select,
    Insert,
    Update,
    Delete,
    Create,
    Drop,
    /// Assign / revoke privileges of other identities (only meaningful on `System`).
    Grant,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Connect => "CONNECT",
            Self::Usage => "USAGE",
            Self::Select => "SELECT",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Create => "CREATE",
            Self::Drop => "DROP",
            Self::Grant => "GRANT",
        };
        f.write_str(s)
    }
}
