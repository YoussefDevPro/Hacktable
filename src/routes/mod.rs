use crate::AuthContext;
use crate::render;
pub use auth::callback;
pub use auth::login;
use axum::Extension;
use axum::response::Html;
pub use main::main_app;
use tera::Context;

mod auth;
mod main;

pub async fn index(auth: Extension<Option<AuthContext>>) -> Html<String> {
    let mut ctx = Context::new();

    match auth.0 {
        Some(v) => {
            ctx.insert(
                "msg",
                &format!("Welcome user {:?}, session {:?}", v.user_id, v.session_id),
            );
            Html::from(render!("index", &ctx))
        }
        _ => {
            ctx.insert("msg", "your a guest pal");
            Html::from(render!("index", &ctx))
        }
    }
}
