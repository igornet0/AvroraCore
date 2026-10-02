use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServerCapabilities {
    pub sql: bool,
    pub transactions: bool,
    pub backup: bool,
    pub diagnostics: bool,
    pub channels: bool,
    pub streams: bool,
    pub triggers: bool,
    pub events: bool,
    pub runtime_schema: bool,
    pub sql_catalog: bool,
    /// Typed schema mutations (CREATE/DROP TABLE/INDEX via Control DDL RPCs).
    pub schema_mutation: bool,
    pub explain: bool,
    pub import: bool,
    pub export: bool,
    pub realtime: bool,
    pub channel_delete: bool,
    pub stream_delete: bool,
    pub trigger_delete: bool,
}

impl ServerCapabilities {
    pub fn core_v1() -> Self {
        Self {
            sql: true,
            transactions: true,
            backup: true,
            diagnostics: true,
            channels: true,
            streams: true,
            triggers: true,
            events: true,
            runtime_schema: true,
            sql_catalog: true,
            schema_mutation: true,
            explain: false,
            import: false,
            export: false,
            realtime: false,
            channel_delete: false,
            stream_delete: false,
            trigger_delete: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelKindWire {
    Internal,
    Tcp,
    Http,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSpecWire {
    pub id: String,
    pub kind: ChannelKindWire,
    #[serde(default)]
    pub bind: Option<String>,
    #[serde(default = "default_capacity")]
    pub capacity: u32,
}

fn default_capacity() -> u32 {
    256
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelInfoWire {
    pub spec: ChannelSpecWire,
    pub started: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamDirectionWire {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamSpecWire {
    pub id: String,
    pub direction: StreamDirectionWire,
    pub channel_id: String,
    pub path_scope: String,
    #[serde(default)]
    pub required_perms: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggerActionWire {
    pub stream_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggerDefWire {
    pub id: String,
    pub on: String,
    pub path_prefix: String,
    pub action: TriggerActionWire,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEventWire {
    pub kind: String,
    pub path: String,
    pub payload: String,
    pub session: String,
    pub role_id: String,
    #[serde(default)]
    pub source_stream: Option<String>,
    pub ts: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SchemaSnapshotWire {
    pub product: String,
    pub channels: Vec<ChannelInfoWire>,
    pub streams: Vec<StreamSpecWire>,
    pub triggers: Vec<TriggerDefWire>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogColumnWire {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    #[serde(default)]
    pub default: Option<String>,
    pub primary_key: bool,
    /// Stable identity fragment (column name); empty on legacy snapshots.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub ordinal: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogIndexWire {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
    #[serde(default)]
    pub id: String,
    #[serde(default = "default_index_type")]
    pub index_type: String,
}

fn default_index_type() -> String {
    "btree".into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogTableWire {
    pub database: String,
    pub schema: String,
    pub name: String,
    pub columns: Vec<CatalogColumnWire>,
    pub indexes: Vec<CatalogIndexWire>,
    #[serde(default = "default_table_kind")]
    pub kind: String,
}

fn default_table_kind() -> String {
    "table".into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSchemaWire {
    pub database: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogDatabaseWire {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CatalogSnapshotWire {
    pub databases: Vec<CatalogDatabaseWire>,
    pub schemas: Vec<CatalogSchemaWire>,
    pub tables: Vec<CatalogTableWire>,
}

/// Lightweight table row for lazy navigator listing (no nested columns/indexes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogTableSummaryWire {
    pub database: String,
    pub schema: String,
    pub name: String,
    #[serde(default = "default_table_kind")]
    pub kind: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogConstraintKindWire {
    PrimaryKey,
    Unique,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogConstraintWire {
    pub id: String,
    pub name: String,
    pub kind: CatalogConstraintKindWire,
    pub columns: Vec<String>,
    #[serde(default)]
    pub referenced_table: Option<String>,
    #[serde(default)]
    pub referenced_columns: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CatalogPageMetaWire {
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnDefWire {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub primary_key: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaMutationResultWire {
    pub operation_id: String,
    pub operation: String,
    pub database: String,
    pub schema: String,
    pub object: String,
    pub object_kind: String,
    pub invalidations: Vec<String>,
    #[serde(default)]
    pub generated_sql: Option<String>,
}


