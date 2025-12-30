use crate::render;
use crate::AuthContext;
pub use auth::callback;
pub use auth::login;
use axum::response::Html;
use axum::Extension;
pub use main::main_app;
use tera::Context;
pub use workspace::new_workspace;
pub use workspace::workspace;

mod auth;
mod main;
mod workspace;

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
