use crate::error::error::Error;
use crate::models::Workspace;
use crate::models::WorkspaceInsert;
use crate::routes::Extension;
use crate::AuthContext;
use crate::DB;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::Form;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use surrealdb::Uuid;

#[derive(Debug)]
pub enum GetWorkspaceError {
    NotFound,
    Forbidden,
    Database(surrealdb::Error),
}

impl From<surrealdb::Error> for GetWorkspaceError {
    fn from(e: surrealdb::Error) -> Self {
        Self::Database(e)
    }
}

#[derive(Debug)]
pub enum CreateWorkspaceError {
    AlreadyExists,
    Database(surrealdb::Error),
}

impl From<surrealdb::Error> for CreateWorkspaceError {
    fn from(e: surrealdb::Error) -> Self {
        // SurrealDB returns an error if record already exists
        if e.to_string().contains("already exists") {
            Self::AlreadyExists
        } else {
            Self::Database(e)
        }
    }
}

pub async fn create_workspace(
    auth: &AuthContext,
    workspace_id: String,
    name: String,
) -> Result<Workspace, CreateWorkspaceError> {
    let insert = WorkspaceInsert {
        name,
        owner: auth.user_id.clone(),
        created_at: Utc::now(),
    };

    let workspace: Option<Workspace> = DB
        .create(("workspace", workspace_id))
        .content(insert)
        .await?;

    Ok(workspace.unwrap())
}

async fn get_workspace(
    auth: &AuthContext,
    workspace_id: &str,
) -> Result<Workspace, GetWorkspaceError> {
    let workspace = DB
        .select::<Option<Workspace>>(("workspace", workspace_id))
        .await?
        .ok_or(GetWorkspaceError::NotFound)?;

    // Ownership check
    if workspace.owner != auth.user_id {
        return Err(GetWorkspaceError::Forbidden);
    }

    Ok(workspace)
}

#[axum_macros::debug_handler]
pub async fn workspace(
    auth: Extension<Option<AuthContext>>,
    id: Path<String>,
) -> Result<Json<Workspace>, Error> {
    let workspace = get_workspace(&auth.0.unwrap(), &id.0)
        .await
        .map_err(|e| match e {
            GetWorkspaceError::NotFound => StatusCode::NOT_FOUND,
            GetWorkspaceError::Forbidden => StatusCode::FORBIDDEN,
            GetWorkspaceError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        })?;
    Ok(Json(workspace))
}

#[derive(Deserialize)]
pub struct CreateWorkspacePayload {
    name: String,
}

#[axum_macros::debug_handler]
pub async fn new_workspace(
    auth: Extension<Option<AuthContext>>,
    Form(payload): Form<CreateWorkspacePayload>,
) -> Result<Json<Workspace>, Error> {
    let workspace = create_workspace(
        &auth.0.unwrap(),
        format!("workspace!{}", Uuid::new_v4()),
        payload.name,
    )
    .await
    .unwrap();
    println!("{workspace:?}");
    Ok(Json(workspace))
}
