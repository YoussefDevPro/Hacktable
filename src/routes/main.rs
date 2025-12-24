use crate::render;
use crate::AuthContext;
use axum::response::Html;
use axum::Extension;
use tera::Context;

pub async fn main_app(Extension(auth): Extension<AuthContext>) -> Html<String> {
    let mut ctx = Context::new();
    ctx.insert(
        "msg",
        &format!(
            "Welcome user {:?}, session {:?}",
            auth.user_id, auth.session_id
        ),
    );
    Html::from(render!("main", &ctx))
}
