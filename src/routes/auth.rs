use crate::error::error::Error;
use crate::models::RefreshToken;
use crate::models::RefreshTokenHash;
use crate::models::Session;
use crate::models::SessionInsert;
use crate::models::User;
use crate::ConnectionInfo;
use crate::DB;
use axum::extract::Query;
use axum::Extension;
use axum::{http::StatusCode, response::Redirect};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    PrivateCookieJar,
};
use hackclub_auth_api::{HCAuth, VerificationStatus};
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;
use surrealdb::sql::Thing;
use time::Duration;
use tracing::{debug, error, info, warn};

#[derive(Deserialize, Debug)]
pub struct Params {
    code: String,
}

pub async fn login() -> Redirect {
    Redirect::to(&HCAuth::new().get_oauth_uri(&[
        "openid",
        "profile",
        "email",
        "name",
        "slack_id",
        "verification_status",
    ]))
}

#[axum_macros::debug_handler]
pub async fn callback(
    Extension(jar): Extension<PrivateCookieJar>,
    connection_info: Extension<ConnectionInfo>,
    Query(params): Query<Params>,
) -> axum::response::Result<(PrivateCookieJar, Redirect), Error> {
    info!("OAuth callback triggered");

    let auth = HCAuth::new();

    let token = auth.exchange_code(params.code).await.map_err(|e| {
        error!("Failed to exchange OAuth code: {:?}", e);
        StatusCode::UNAUTHORIZED
    })?;

    debug!("OAuth code exchanged successfully");

    let claims = match auth.verify_jwt_token(token.id_token).await {
        Ok(claims) => {
            debug!("JWT verified for sub={}", claims.sub);
            claims
        }
        Err(e) => {
            error!("JWT verification failed: {:?}", e);
            return Err(StatusCode::UNAUTHORIZED.into());
        }
    };

    if claims.email.is_none() || !claims.email_verified.unwrap_or(false) {
        warn!("Unverified or missing email for sub={}", claims.sub);
        return Err(StatusCode::UNAUTHORIZED.into());
    }

    match claims.verification_status {
        Some(VerificationStatus::Rejected) => {
            warn!("User {} rejected by verification", claims.sub);
            return Err(StatusCode::FORBIDDEN.into());
        }
        Some(VerificationStatus::Pending) => {
            info!("User {} pending verification", claims.sub);
            return Ok((jar, Redirect::to("/")));
        }
        Some(VerificationStatus::NotFound) => {
            warn!("User {} not found in verification system", claims.sub);
            return Ok((jar, Redirect::to("/")));
        }
        Some(VerificationStatus::Ineligible) => {
            warn!("User {} ineligible", claims.sub);
            return Err(StatusCode::FORBIDDEN.into());
        }
        _ => {}
    };

    let user_id = Thing::from(("user", claims.sub.as_str()));
    let email = claims.email.clone().unwrap();
    let name = claims.name.clone().unwrap();

    info!("Upserting user {} ({})", user_id, email);

    let _user: Option<User> = DB
        .query(
            "
            UPSERT user:$sub
            SET
              email = $email,
              name = $name,
              created_at = time::now();
            SELECT * FROM user:$sub;
            ",
        )
        .bind(("sub", user_id.clone()))
        .bind(("email", email))
        .bind(("name", name))
        .await
        .map_err(|e| {
            error!("Database error while upserting user {}: {:?}", user_id, e);
            e
        })?
        .take(1)?;

    let refresh = RefreshToken(token.refresh_token.ok_or_else(|| {
        error!("Missing refresh token for user {}", user_id);
        StatusCode::UNAUTHORIZED
    })?);

    let refresh_hash = hash_refresh(&refresh);

    let session_insert = SessionInsert::new(
        user_id.clone(),
        refresh_hash,
        24 * 30,
        Some(connection_info.user_agent.to_owned()),
        Some(connection_info.ip.to_owned()),
    );

    let session: Session = DB
        .create("session")
        .content(session_insert)
        .await
        .map_err(|e| {
            error!("Failed to create session for {}: {:?}", user_id, e);
            e
        })?
        .unwrap();

    info!(
        "Session created for user {} (session_id={})",
        user_id,
        session.id.as_ref().unwrap()
    );

    let mut cookie = Cookie::new("session", session.id.unwrap().to_string());
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_path("/");
    cookie.set_max_age(Duration::days(5));

    let jar = jar.add(cookie);

    info!(
        "Login successful for user {} from ip={} ua={:?}",
        user_id, connection_info.ip, connection_info.user_agent
    );

    Ok((jar, Redirect::to("/app")))
}

fn hash_refresh(rt: &RefreshToken) -> RefreshTokenHash {
    let hash = Sha256::digest(rt.0.as_bytes());
    RefreshTokenHash(format!("{:x}", hash))
}
