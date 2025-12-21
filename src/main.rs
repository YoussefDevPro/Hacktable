use axum::routing::delete;
use axum::routing::post;
use axum::routing::put;
use axum::{routing::get, Router};
use std::sync::LazyLock;
use surrealdb::engine::remote::ws::Client;
use surrealdb::engine::remote::ws::Ws;
use surrealdb::opt::auth::Root;
use surrealdb::Surreal;

mod error;
mod routes;

static DB: LazyLock<Surreal<Client>> = LazyLock::new(Surreal::init);

#[tokio::main]
async fn main() -> Result<(), error::error::Error> {
    DB.connect::<Ws>("localhost:8080").await?;

    DB.signin(Root {
        username: "root",
        password: "secret",
    })
    .await?;

    DB.use_ns("main").use_db("main").await?;

    DB.query(
        "
DEFINE TABLE IF NOT EXISTS person SCHEMALESS
    PERMISSIONS FOR 
        CREATE, SELECT WHERE $auth,
        FOR UPDATE, DELETE WHERE created_by = $auth;
DEFINE FIELD IF NOT EXISTS name ON TABLE person TYPE string;
DEFINE FIELD IF NOT EXISTS created_by ON TABLE person VALUE $auth READONLY;

DEFINE INDEX IF NOT EXISTS unique_name ON TABLE user FIELDS name UNIQUE;
DEFINE ACCESS IF NOT EXISTS account ON DATABASE TYPE RECORD
SIGNUP ( CREATE user SET name = $name, pass = crypto::argon2::generate($pass) )
SIGNIN ( SELECT * FROM user WHERE name = $name AND crypto::argon2::compare(pass, $pass) )
DURATION FOR TOKEN 15m, FOR SESSION 12h
;",
    )
    .await?;
    // build our application with a single route
    let app = Router::new()
        .route("/", get(routes::paths))
        .route("/person/{id}", post(routes::create_person))
        .route("/person/{id}", get(routes::read_person))
        .route("/person/{id}", put(routes::update_person))
        .route("/person/{id}", delete(routes::delete_person))
        .route("/people", get(routes::list_people))
        .route("/session", get(routes::session))
        .route("/new_user", get(routes::make_new_user))
        .route("/new_token", get(routes::get_new_token));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
