//! Phase 7.3 — framed local IPC protocol.

mod codec;
mod error;
mod frame;
mod framed;
mod limits;
mod message;
mod unlock_blob;
mod validate;

pub use codec::{decode_payload, encode_payload};
pub use error::{sanitize_client_message, ProtocolError, ProtocolErrorCode, Result};
pub use frame::{decode_frame, encode_frame, Frame, FrameHeader, MessageType, HEADER_SIZE};
pub use framed::{build_frame, read_frame, write_frame, FramedConnection};
pub use limits::{
    RemoteLimits, ProtocolLimits, DEFAULT_MAX_FRAME_SIZE, DEFAULT_MAX_IN_FLIGHT_REQUESTS,
    DEFAULT_MAX_PARAMETER_SIZE, DEFAULT_MAX_PARAMS, DEFAULT_MAX_REQUESTS_PER_CONNECTION,
    DEFAULT_MAX_SQL_SIZE, DEFAULT_MAX_UNLOCK_BLOB_SIZE,
};
pub use message::{
    BackupListItem, ControlRequest, ControlResponse, DataRequest, DataResponse, DiagnosticsWire,
    HandshakeRequest, HandshakeResponse, RequestEnvelope, ResponseEnvelope, ResponseStatus,
    SqlCell, SqlParam, SqlRow, SqlResult, VaultStateWire,
};
pub use unlock_blob::{
    unlock_blob_aad, validate_unlock_blob, UnlockBlob, UNLOCK_BLOB_NONCE_LEN,
    UNLOCK_BLOB_VERSION, UNLOCK_MATERIAL_LEN,
};
pub use validate::{validate_control_request, validate_data_request};

pub const PROTOCOL_VERSION: u16 = 1;
