use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::error::Error;

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl From<Error> for ApiError {
    fn from(err: Error) -> Self {
        let status = match &err {
            Error::Vault(v) => match v {
                dmc_vault::Error::AccessDenied(_, _) | dmc_vault::Error::CannotDelegate(_) => {
                    StatusCode::FORBIDDEN
                }
                dmc_vault::Error::NotFound(_) | dmc_vault::Error::UnknownNode(_) => {
                    StatusCode::NOT_FOUND
                }
                dmc_vault::Error::Revoked(_)
                | dmc_vault::Error::AlreadyExists
                | dmc_vault::Error::AlreadyUnlocked => StatusCode::CONFLICT,
                dmc_vault::Error::Locked => StatusCode::LOCKED,
                dmc_vault::Error::WrongMasterKey
                | dmc_vault::Error::InvalidMasterKey
                | dmc_vault::Error::WrongMasterPassword => StatusCode::UNAUTHORIZED,
                dmc_vault::Error::InvalidPath(_)
                | dmc_vault::Error::MissingParent(_)
                | dmc_vault::Error::NotInitialized
                | dmc_vault::Error::Persist(_)
                | dmc_vault::Error::InvalidMasterPassword(_)
                | dmc_vault::Error::KeyPassNotFound
                | dmc_vault::Error::KeyPassDbMismatch => StatusCode::BAD_REQUEST,
                dmc_vault::Error::UnwrapFailed
                | dmc_vault::Error::AeadFailed
                | dmc_vault::Error::KdfFailed
                | dmc_vault::Error::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            },
            Error::Locked => StatusCode::LOCKED,
            Error::UnknownSession(_)
            | Error::UnknownRole(_)
            |             Error::UnknownStream(_)
            | Error::UnknownChannel(_)
            | Error::UnknownTrigger(_)
            | Error::UnknownSubscription(_)
            | Error::UnknownGroup(_)
            | Error::UnknownMember(_)
            | Error::UnknownSubsystem(_) => StatusCode::NOT_FOUND,
            Error::AuthorizationDenied(_) => StatusCode::FORBIDDEN,
            Error::StaleDelivery(_) => StatusCode::CONFLICT,
            Error::UnknownDelivery(_) => StatusCode::NOT_FOUND,
            Error::UnknownDlq(_) | Error::UnknownGroupDlqEntry { .. } => StatusCode::NOT_FOUND,
            Error::RetryBackoff { .. } | Error::GroupRetryBackoff { .. } => StatusCode::TOO_MANY_REQUESTS,
            Error::Backpressure { .. } => StatusCode::TOO_MANY_REQUESTS,
            Error::DeliveryExhausted { .. } | Error::GroupRetryExhausted { .. } => StatusCode::CONFLICT,
            Error::Invalid(_)
            | Error::OutsideScope(_)
            | Error::NotInbound(_)
            | Error::NotOutbound(_)
            | Error::TrimBeyondWatermark { .. }
            | Error::TrimUnsafe
            | Error::HistoryUnavailable { .. } => StatusCode::BAD_REQUEST,
            Error::ChannelExists(_) | Error::StreamExists(_) | Error::GroupExists(_) => {
                StatusCode::CONFLICT
            }
            Error::GroupNotEmpty(_) | Error::MemberExists(_) | Error::MemberNotActive(_) | Error::StaleGeneration { .. } | Error::NotAssigned { .. } => {
                StatusCode::CONFLICT
            }
            Error::Storage(_) | Error::Journal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self::new(status, err.to_string())
    }
}

impl From<dmc_vault::Error> for ApiError {
    fn from(err: dmc_vault::Error) -> Self {
        Error::from_vault(err).into()
    }
}

impl From<dmc_runtime::Error> for ApiError {
    fn from(err: dmc_runtime::Error) -> Self {
        Error::from(err).into()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
