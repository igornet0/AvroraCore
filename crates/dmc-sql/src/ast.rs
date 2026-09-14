use crate::types::{SqlType, SqlValue};

#[derive(Clone, Debug)]
pub enum Statement {
    CreateTable(CreateTable),
    AlterTable(AlterTable),
    DropTable(DropTable),
    CreateIndex(CreateIndex),
    DropIndex(DropIndex),
    CreateSchema(CreateSchema),
    DropSchema { name: String, if_exists: bool },
    CreateView(CreateView),
    DropView { schema: String, name: String, if_exists: bool },
    CreateDatabase { name: String, if_not_exists: bool },
    Insert(Insert),
    Update(Update),
    Delete(Delete),
    Select(Select),
    Begin,
    Commit,
    Rollback,
    Set,
}

#[derive(Clone, Debug)]
pub struct CreateTable {
    pub schema: String,
    pub name: String,
    pub if_not_exists: bool,
    pub columns: Vec<ColumnDef>,
}

#[derive(Clone, Debug)]
pub struct ColumnDef {
    pub name: String,
    pub data_type: SqlType,
    pub nullable: bool,
    pub default: Option<String>,
    pub primary_key: bool,
}

#[derive(Clone, Debug)]
pub struct AlterTable {
    pub schema: String,
    pub name: String,
    pub op: AlterOp,
}

#[derive(Clone, Debug)]
pub enum AlterOp {
    AddColumn { column: ColumnDef, if_not_exists: bool },
    DropColumn { name: String, if_exists: bool },
}

#[derive(Clone, Debug)]
pub struct DropTable {
    pub schema: String,
    pub name: String,
    pub if_exists: bool,
}

#[derive(Clone, Debug)]
pub struct CreateIndex {
    pub name: String,
    pub schema: String,
    pub table: String,
    pub columns: Vec<String>,
    pub unique: bool,
    pub if_not_exists: bool,
}

#[derive(Clone, Debug)]
pub struct DropIndex {
    pub name: String,
    pub if_exists: bool,
}

#[derive(Clone, Debug)]
pub struct CreateSchema {
    pub name: String,
    pub if_not_exists: bool,
}

#[derive(Clone, Debug)]
pub struct CreateView {
    pub schema: String,
    pub name: String,
    pub definition: String,
    pub or_replace: bool,
}

#[derive(Clone, Debug)]
pub struct Insert {
    pub schema: String,
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<SqlValue>>,
}

#[derive(Clone, Debug)]
pub struct Update {
    pub schema: String,
    pub table: String,
    pub assignments: Vec<(String, SqlValue)>,
    pub selection: Option<Predicate>,
}

#[derive(Clone, Debug)]
pub struct Delete {
    pub schema: String,
    pub table: String,
    pub selection: Option<Predicate>,
}

#[derive(Clone, Debug)]
pub struct Select {
    pub schema: Option<String>,
    pub table: Option<String>,
    pub columns: Vec<SelectItem>,
    pub selection: Option<Predicate>,
}

#[derive(Clone, Debug)]
pub enum SelectItem {
    Wildcard,
    Column(String),
    Value(SqlValue),
}

#[derive(Clone, Debug)]
pub enum Predicate {
    Eq { column: String, value: SqlValue },
    And(Box<Predicate>, Box<Predicate>),
}
