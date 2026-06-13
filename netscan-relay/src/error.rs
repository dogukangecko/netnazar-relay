use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use netscan_proto::ApiError;

/// Relay handler hata türü; tutarlı ApiError JSON'a dönüşür.
#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    BadRequest(String),
    NotFound,
    Unavailable(String),
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "geçersiz veya eksik kimlik bilgisi".to_string(),
            ),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m),
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "bulunamadı".to_string(),
            ),
            AppError::Unavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable", m),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, "internal", m),
        };
        (status, Json(ApiError { code: code.to_string(), message })).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        // Hata detayını sunucu tarafında logla; istemciye genel mesaj dön (şema sızıntısı yok).
        eprintln!("db error: {e}");
        AppError::Internal("sunucu hatası".to_string())
    }
}
