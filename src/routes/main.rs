use crate::render;
use crate::AuthContext;
use axum::response::Html;
use axum::Extension;
use tera::Context;

pub async fn main_app(auth: Extension<Option<AuthContext>>) -> Html<String> {
    let mut ctx = Context::new();

    match auth.0 {
        Some(v) => {
            ctx.insert(
                "msg",
                &format!("Welcome user {}, session {}", v.user_id.id, v.session_id.id),
            );
            Html::from(render!("main", &ctx))
        }
        _ => {
            ctx.insert("msg", "your a guest pal");
            Html::from(render!("main", &ctx))
        }
    }
}
