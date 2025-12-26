use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Datetime;
use surrealdb::sql::Thing;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Text,
    Number,
    Bool,
    Date,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Option<Thing>,
    pub email: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: Option<Thing>,
    pub name: String,
    pub owner: Thing, // User
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Base {
    pub id: Option<Thing>,
    pub workspace: Thing, // Workspace
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableDef {
    pub id: Option<Thing>,
    pub base: Thing, // Base
    pub name: String,
    pub order: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub id: Option<Thing>,
    pub table: Thing, // Table_def
    pub name: String,
    pub field_type: FieldType, // "text", "number", "bool", etc
    pub config: serde_json::Value,
    pub order: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: Option<Thing>,
    pub table: Thing, // Table_def
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cell {
    pub id: Option<Thing>,
    pub record: Thing, // Record
    pub field: Thing,  // Field
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relation {
    pub id: Option<Thing>,
    pub from_record: Thing, // Record1
    pub to_record: Thing,   // Record2 != Record1
    pub field: Thing,       // Field
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Option<Thing>,
    pub user: Thing, // user:xxxx
    pub refresh_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

// just uh, to make everything safer :p
// bc uh, im a security maniac :3
#[derive(Debug, Clone, Serialize)]
pub struct SessionInsert {
    pub user: Thing,
    pub refresh_hash: String,
    pub created_at: Datetime,
    pub expires_at: Datetime,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

impl SessionInsert {
    pub fn new(
        user: Thing,
        refresh_hash: RefreshTokenHash,
        ttl_hours: i64,
        user_agent: Option<String>,
        ip: Option<String>,
    ) -> Self {
        let now: DateTime<Utc> = Utc::now();
        let expires_at = now + Duration::hours(ttl_hours);

        Self {
            user,
            refresh_hash: refresh_hash.0,
            created_at: Datetime::from(now),
            expires_at: Datetime::from(expires_at),
            user_agent,
            ip,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: Thing,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// user id
    pub sub: Thing,

    /// session id
    pub sid: Thing,

    /// expiration timestamp (unix)
    pub exp: i64,
}

// i readed a blog abt strong typing, so i tought its a gud idea to actually practice it
#[derive(Debug, Clone)]
pub struct RefreshToken(pub String);

#[derive(Debug, Clone, Serialize)]
pub struct RefreshTokenHash(pub String);

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: Thing,
    pub session_id: Thing,
}

// Source - https://stackoverflow.com/a/79331661
// Posted by sudoExclamationExclamation
// Retrieved 2025-12-23, License - CC BY-SA 4.0

#[derive(Clone, Debug)]
struct ConnectionInfo {
    ip: String,
    user_agent: String,
}
