use crate::models::AuthContext;
use crate::models::Session;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::FromRef;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Html;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::{routing::get, Router};
use axum_extra::extract::cookie::Key;
use axum_extra::extract::PrivateCookieJar;
use axum_extra::TypedHeader;
use chrono::Utc;
use headers::UserAgent;
use lazy_static::lazy_static;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::LazyLock;
use surrealdb::engine::remote::ws::Client;
use surrealdb::engine::remote::ws::Ws;
use surrealdb::opt::auth::Root;
use surrealdb::sql::Thing;
use surrealdb::Surreal;
use tera::Tera;

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

pub async fn auth_middleware(mut req: Request<Body>, next: Next) -> Response {
    if let Some(state) = req.extensions().get::<AppState>() {
        // Manually create PrivateCookieJar using the key
        let jar = PrivateCookieJar::from_headers(req.headers(), state.key.clone());

        if let Some(session_cookie) = jar.get("session") {
            if let Ok(session_id) = session_cookie.value().parse::<String>() {
                if let Ok(Some(session)) = DB
                    .select::<Option<Session>>(("session", session_id.as_str()))
                    .await
                {
                    if session.expires_at >= Utc::now() {
                        let auth = AuthContext {
                            user_id: session.user.clone(),
                            session_id: Thing::from(("session", session_id.as_str())),
                        };
                        req.extensions_mut().insert(auth);
                    } else {
                        let _ = DB.delete::<Option<Session>>(("session", session_id)).await;
                    }
                }
            }
        }

        // Put the jar back into request extensions so handlers can reuse it
        req.extensions_mut().insert(jar);
    }

    next.run(req).await
}

#[derive(Clone)]
struct AppState(Arc<InnerState>);

// deref so you can still access the inner fields easily
impl Deref for AppState {
    type Target = InnerState;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct InnerState {
    key: Key,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
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
    let user_agent = match user_agent {
        Some(u) => u,
        None => return Html("UserAgent is missing.").into_response(),
    };

    request.extensions_mut().insert(ConnectionInfo {
        ip: addr.to_string(),
        user_agent: user_agent.to_string(),
    });
    next.run(request).await
}

#[tokio::main]
async fn main() -> Result<(), error::error::Error> {
    let state = AppState(
        // You probably don't wanna generate a new one each time the app starts though
        Arc::new(InnerState {
            key: Key::generate(),
        }),
    );

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
        // public routes
        .route("/", get(routes::index))
        .route("/login/hackclub", get(routes::login))
        .route("/hackclub/callback", get(routes::callback))
        .route("/app", get(routes::main_app))
        .layer(axum::middleware::from_fn(auth_middleware))
        .layer(axum::middleware::from_fn(connection_info_middleware))
        .with_state(state)
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
