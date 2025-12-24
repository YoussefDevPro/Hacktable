pub mod error {
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::Json;
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("  Dawabase error")]
        Db,
    }

    impl IntoResponse for Error {
        fn into_response(self) -> Response {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(self.to_string())).into_response()
        }
    }
    impl From<StatusCode> for Error {
        fn from(value: StatusCode) -> Self {
            value.into()
        }
    }

    impl From<surrealdb::Error> for Error {
        fn from(value: surrealdb::Error) -> Self {
            eprint!(" {value}");
            Self::Db
        }
    }
}
