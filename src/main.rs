use crate::models::AuthContext;
use crate::models::Session;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Html;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::post;
use axum::{routing::get, Router};
use axum_extra::TypedHeader;
use chrono::Utc;
use headers::UserAgent;
use lazy_static::lazy_static;
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::sync::OnceLock;
use surrealdb::engine::remote::ws::Client;
use surrealdb::engine::remote::ws::Ws;
use surrealdb::opt::auth::Root;
use surrealdb::sql::Thing;
use surrealdb::Surreal;
use tera::Tera;
use tower_cookies::CookieManagerLayer;
use tower_cookies::Cookies;
use tower_cookies::Key;

mod error;
mod models;
mod routes;

lazy_static! {
    static ref TEMPLATES: Tera = {
        match Tera::new("templates/**/*.html.tera") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        }
    };
}

lazy_static! {
    static ref DB: LazyLock<Surreal<Client>> = LazyLock::new(Surreal::init);
}

#[macro_export]
macro_rules! render {
    ($name:expr, $context:expr) => {
        $crate::TEMPLATES
            .render(&format!("{}.html.tera", $name), $context)
            .unwrap()
    };
}

lazy_static! {
    static ref KEY: OnceLock<Key> = OnceLock::new();
}

pub async fn auth_middleware(cookies: Cookies, mut req: Request<Body>, next: Next) -> Response {
    println!("auth_middleware hit: {}", req.uri());
    let key = KEY.get().unwrap();
    let private_cookies = cookies.private(key);

    let session_id = match private_cookies
        .get("session")
        .map(|c| c.value().to_string())
    {
        Some(s) => s,
        None => {
            req.extensions_mut().insert::<Option<AuthContext>>(None);
            return next.run(req).await;
        }
    };

    println!("Session ID from cookie: {}", session_id);

    let session_data = match DB.select::<Option<Session>>(("session", &session_id)).await {
        Ok(Some(s)) if s.expires_at >= Utc::now() => Some(s),
        _ => None,
    };

    if let Some(s) = session_data {
        let auth = AuthContext {
            user_id: s.user.clone(),
            session_id: Thing::from(("session", session_id.as_str())),
        };
        println!("Authenticated user: {:?}", s.user);
        req.extensions_mut().insert(Some(auth));
    } else {
        println!("No valid session found");
        req.extensions_mut().insert::<Option<AuthContext>>(None);
    }

    next.run(req).await
}

// Source - https://stackoverflow.com/a/79331661
// Posted by sudoExclamationExclamation
// Retrieved 2025-12-23, License - CC BY-SA 4.0

#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    ip: String,
    user_agent: String,
}

// Source - https://stackoverflow.com/a/79331661
// Posted by sudoExclamationExclamation
// Retrieved 2025-12-23, License - CC BY-SA 4.0

async fn connection_info_middleware(
    user_agent: Option<TypedHeader<UserAgent>>,
    addr: ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    println!("connection info hit: {}", request.uri());

    let user_agent = match user_agent {
        Some(u) => u,
        None => return Html("UserAgent is missing.").into_response(),
    };

    request.extensions_mut().insert(ConnectionInfo {
        ip: addr.to_string(),
        user_agent: user_agent.to_string(),
    });
    println!("connection info passing through");

    next.run(request).await
}

#[tokio::main]
async fn main() -> Result<(), error::error::Error> {
    println!("starting");
    let _ = KEY.set(Key::generate());
    DB.connect::<Ws>("localhost:8080").await?;

    DB.signin(Root {
        username: "root",
        password: "secret",
    })
    .await?;

    DB.use_ns("main").use_db("main").await?;

    DB.query(include_str!("models/models.surql")).await?;

    for t in TEMPLATES.get_template_names() {
        println!("{}", t);
    }

    let app: Router = Router::new()
        .route("/login/hackclub", get(routes::login))
        .route("/hackclub/callback", get(routes::callback))
        .route("/", get(routes::index))
        .route("/app", get(routes::main_app))
        .route("/app/workspace", post(routes::new_workspace))
        .route("/app/workspace/{id}", get(routes::workspace))
        .layer(axum::middleware::from_fn(connection_info_middleware))
        .layer(axum::middleware::from_fn(auth_middleware))
        .layer(CookieManagerLayer::new())
        .nest("/static", axum_static::static_router("./static"));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
    Ok(())
}
