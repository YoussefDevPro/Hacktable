use crate::render;
pub use auth::callback;
pub use auth::login;
use axum::response::Html;
pub use main::main_app;
use tera::Context;

mod auth;
mod main;

pub async fn index() -> Html<String> {
    Html::from(render!("index", &Context::new()))
}
