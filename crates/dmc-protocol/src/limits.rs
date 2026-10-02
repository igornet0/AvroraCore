pub const DEFAULT_MAX_FRAME_SIZE: u32 = 1_048_576;
pub const DEFAULT_MAX_SQL_SIZE: u32 = 1_048_576;
pub const DEFAULT_MAX_PARAMS: u32 = 256;
pub const DEFAULT_MAX_PARAMETER_SIZE: u32 = 65_536;
pub const DEFAULT_MAX_IN_FLIGHT_REQUESTS: u32 = 32;
pub const DEFAULT_MAX_REQUESTS_PER_CONNECTION: u32 = 10_000;
pub const DEFAULT_MAX_UNLOCK_BLOB_SIZE: u32 = 4096;
pub const DEFAULT_MAX_RUNTIME_ID_LEN: u32 = 128;
pub const DEFAULT_MAX_INGEST_PAYLOAD: u32 = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolLimits {
    pub max_frame_size: u32,
    pub max_connections: u32,
    pub max_concurrent_requests: u32,
    pub read_timeout_ms: u64,
    pub write_timeout_ms: u64,
    pub idle_timeout_ms: u64,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_connections: 64,
            max_concurrent_requests: 32,
            read_timeout_ms: 30_000,
            write_timeout_ms: 30_000,
            idle_timeout_ms: 300_000,
        }
    }
}

/// Remote transport limits (7.4). Frame limits validated before payload allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteLimits {
    pub frame: ProtocolLimits,
    pub max_sql_size: u32,
    pub max_params: u32,
    pub max_parameter_size: u32,
    pub max_in_flight_requests: u32,
    pub max_requests_per_connection: u32,
    pub max_unlock_blob_size: u32,
    pub max_runtime_id_len: u32,
    pub max_ingest_payload: u32,
}

impl Default for RemoteLimits {
    fn default() -> Self {
        Self {
            frame: ProtocolLimits {
                max_connections: 128,
                max_concurrent_requests: DEFAULT_MAX_IN_FLIGHT_REQUESTS,
                ..ProtocolLimits::default()
            },
            max_sql_size: DEFAULT_MAX_SQL_SIZE,
            max_params: DEFAULT_MAX_PARAMS,
            max_parameter_size: DEFAULT_MAX_PARAMETER_SIZE,
            max_in_flight_requests: DEFAULT_MAX_IN_FLIGHT_REQUESTS,
            max_requests_per_connection: DEFAULT_MAX_REQUESTS_PER_CONNECTION,
            max_unlock_blob_size: DEFAULT_MAX_UNLOCK_BLOB_SIZE,
            max_runtime_id_len: DEFAULT_MAX_RUNTIME_ID_LEN,
            max_ingest_payload: DEFAULT_MAX_INGEST_PAYLOAD,
        }
    }
}

impl RemoteLimits {
    pub fn protocol(&self) -> &ProtocolLimits {
        &self.frame
    }
}
