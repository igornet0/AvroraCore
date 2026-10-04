//! Phase 7.3 — framed local IPC protocol.

mod codec;
mod error;
mod frame;
mod framed;
mod limits;
mod message;
mod runtime;
mod unlock_blob;
mod validate;

pub use codec::{decode_payload, encode_payload};
pub use error::{sanitize_client_message, ProtocolError, ProtocolErrorCode, Result};
pub use frame::{decode_frame, encode_frame, Frame, FrameHeader, MessageType, HEADER_SIZE};
pub use framed::{build_frame, read_frame, write_frame, FramedConnection};
pub use limits::{
    RemoteLimits, ProtocolLimits, DEFAULT_MAX_FRAME_SIZE, DEFAULT_MAX_IN_FLIGHT_REQUESTS,
    DEFAULT_MAX_INGEST_PAYLOAD, DEFAULT_MAX_PARAMETER_SIZE, DEFAULT_MAX_PARAMS,
    DEFAULT_MAX_REQUESTS_PER_CONNECTION, DEFAULT_MAX_RUNTIME_ID_LEN, DEFAULT_MAX_SQL_SIZE,
    DEFAULT_MAX_UNLOCK_BLOB_SIZE,
};
pub use message::{
    ClientGrantWire,
    BackupListItem, ControlRequest, ControlResponse, DataRequest, DataResponse, DiagnosticsWire,
    HandshakeRequest, HandshakeResponse, RequestEnvelope, ResponseEnvelope, ResponseStatus,
    SqlCell, SqlParam, SqlRow, SqlResult, VaultStateWire,
};
pub use runtime::{
    CatalogColumnWire, CatalogConstraintKindWire, CatalogConstraintWire, CatalogDatabaseWire,
    CatalogIndexWire, CatalogPageMetaWire, CatalogSchemaWire, CatalogSnapshotWire,
    CatalogTableSummaryWire, CatalogTableWire, ChannelInfoWire, ChannelKindWire, ChannelSpecWire,
    ColumnDefWire, RuntimeEventWire, SchemaMutationResultWire, SchemaSnapshotWire,
    ServerCapabilities, StreamDirectionWire, StreamSpecWire, TriggerActionWire, TriggerDefWire,
};
pub use unlock_blob::{
    unlock_blob_aad, validate_unlock_blob, UnlockBlob, UNLOCK_BLOB_NONCE_LEN,
    UNLOCK_BLOB_VERSION, UNLOCK_MATERIAL_LEN,
};
pub use validate::{validate_control_request, validate_data_request};

pub const PROTOCOL_VERSION: u16 = 1;
