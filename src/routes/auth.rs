use crate::error::error::Error;
use crate::models::RefreshToken;
use crate::models::RefreshTokenHash;
use crate::models::Session;
use crate::models::SessionInsert;
use crate::models::User;
use crate::ConnectionInfo;
use crate::DB;
use crate::KEY;
use axum::extract::Query;
use axum::Extension;
use axum::{http::StatusCode, response::Redirect};
use hackclub_auth_api::{HCAuth, VerificationStatus};
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use surrealdb::sql::Thing;
use time::Duration;
use tower_cookies::cookie::SameSite;
use tower_cookies::Cookie;
use tower_cookies::Cookies;

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
    connection_info: Extension<ConnectionInfo>,
    cookies: Cookies,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Result<Redirect, Error> {
    println!("➡️ OAuth callback triggered");

    let auth = HCAuth::new();

    let code = match params.get("code") {
        Some(code) => code.to_string(),
        None => {
            println!("❌ Missing OAuth code parameter");
            return Err(StatusCode::BAD_REQUEST.into());
        }
    };

    println!("🔑 OAuth code received");

    let token = match auth.exchange_code(code).await {
        Ok(token) => {
            println!("✅ OAuth code exchanged successfully");
            token
        }
        Err(e) => {
            println!("❌ Failed to exchange OAuth code: {:?}", e);
            return Err(StatusCode::UNAUTHORIZED.into());
        }
    };

    let _claims = match auth.verify_jwt_token(token.id_token).await {
        Ok(claims) => {
            println!("✅ JWT verified for sub={}", claims.sub);
            claims
        }
        Err(e) => {
            println!("❌ JWT verification failed: {:?}", e);
            return Err(StatusCode::UNAUTHORIZED.into());
        }
    };

    let resp = match auth.get_identity(token.access_token.unwrap()).await {
        Ok(v) => v,
        Err(e) => {
            println!("❗️ : {e:?}");
            return Ok(Redirect::to("/"));
        }
    };

    if resp.identity.primary_email.is_empty() {
        println!(
            "❌ Email missing or not verified for sub={}",
            resp.identity.id
        );
        return Err(StatusCode::UNAUTHORIZED.into());
    }

    match resp.identity.verification_status {
        Some(VerificationStatus::Rejected) => {
            println!("❌ User {} rejected by verification", resp.identity.id);
            return Err(StatusCode::FORBIDDEN.into());
        }
        Some(VerificationStatus::Pending) => {
            println!("⏳ User {} pending verification", resp.identity.id);
            return Ok(Redirect::to("/"));
        }
        Some(VerificationStatus::NotFound) => {
            println!(
                "⚠️ User {} not found in verification system",
                resp.identity.id
            );
            return Ok(Redirect::to("/"));
        }
        Some(VerificationStatus::Ineligible) => {
            println!("❌ User {} ineligible", resp.identity.id);
            return Err(StatusCode::FORBIDDEN.into());
        }
        _ => {
            println!("✅ Verification status OK");
        }
    }

    let user_id = Thing::from(("user", resp.identity.id.as_str()));
    let email = resp.identity.primary_email.clone();
    let name = resp.identity.first_name.unwrap() + &resp.identity.last_name.unwrap();

    println!("📝 Upserting user {} ({})", user_id, email);

    let _user: Option<User> = match DB
        .query(
            "
            UPSERT $id
            SET
              email = $email,
              name = $name,
              created_at = time::now();
            SELECT * FROM $id;
            ",
        )
        .bind(("id", user_id.clone()))
        .bind(("email", email))
        .bind(("name", name))
        .await
    {
        Ok(mut res) => res.take(1)?,
        Err(e) => {
            println!(
                "❌ Database error while upserting user {}: {:?}",
                user_id, e
            );
            return Err(e.into());
        }
    };

    let refresh_token = match token.refresh_token {
        Some(rt) => rt,
        None => {
            println!("❌ Missing refresh token for user {}", user_id);
            return Err(StatusCode::UNAUTHORIZED.into());
        }
    };

    let refresh_hash = hash_refresh(&RefreshToken(refresh_token));

    let session_insert = SessionInsert::new(
        user_id.clone(),
        refresh_hash,
        24 * 30,
        Some(connection_info.user_agent.to_owned()),
        Some(connection_info.ip.to_owned()),
    );

    let session: Session = match DB.create("session").content(session_insert).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            println!("❌ Session creation returned None");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into());
        }
        Err(e) => {
            println!("❌ Failed to create session for {}: {:?}", user_id, e);
            return Err(e.into());
        }
    };

    let session_id = session.id.as_ref().unwrap().to_string();
    let session_id_clean = session_id
        .strip_prefix("session:")
        .unwrap_or(&session_id)
        .to_string();

    println!("🧾 Session created for user {} ", user_id);

    let key = KEY.get().unwrap();
    let private_cookies = cookies.private(key);

    let mut cookie = Cookie::new("session", session_id_clean);
    cookie.set_http_only(false);
    cookie.set_secure(false);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_max_age(Duration::days(5));
    cookie.set_expires(time::OffsetDateTime::now_utc() + Duration::days(5));

    private_cookies.add(cookie);

    println!(
        "🎉 Login successful for user {} (ip={}, ua={:?})",
        user_id, connection_info.ip, connection_info.user_agent
    );

    Ok(Redirect::to("/app"))
}

fn hash_refresh(rt: &RefreshToken) -> RefreshTokenHash {
    let hash = Sha256::digest(rt.0.as_bytes());
    RefreshTokenHash(format!("{:x}", hash))
}
