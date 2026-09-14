use std::io::{Read, Write};

use dmc_protocol::{
    build_frame, decode_payload, encode_payload, ControlRequest, ControlResponse, DataRequest,
    DataResponse, FramedConnection, HandshakeRequest, HandshakeResponse, MessageType,
    ProtocolError, ProtocolErrorCode, ProtocolLimits, RemoteLimits, RequestEnvelope,
    ResponseEnvelope, ResponseStatus, Result, PROTOCOL_VERSION,
};

pub struct ProtocolClient<C: Read + Write> {
    conn: FramedConnection<C>,
    next_request_id: u64,
    limits: RemoteLimits,
}

impl<C: Read + Write> ProtocolClient<C> {
    pub fn new(conn: C, limits: RemoteLimits) -> Self {
        Self {
            conn: FramedConnection::new(conn, limits.frame),
            next_request_id: 1,
            limits,
        }
    }

    pub fn with_protocol_limits(conn: C, limits: ProtocolLimits) -> Self {
        Self::new(conn, RemoteLimits {
            frame: limits,
            ..RemoteLimits::default()
        })
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        id
    }

    pub fn handshake(&mut self, client_id: &str) -> Result<HandshakeResponse> {
        let body = HandshakeRequest {
            protocol_version: PROTOCOL_VERSION,
            client_id: client_id.into(),
        };
        let payload = encode_payload(&body, self.limits.protocol())?;
        self.conn
            .write_frame(&build_frame(MessageType::HandshakeRequest, payload))?;
        let frame = self.conn.read_frame()?;
        if frame.header.message_type != MessageType::HandshakeResponse {
            return Err(ProtocolError::InvalidFrame(
                "expected handshake response".into(),
            ));
        }
        decode_payload(&frame.payload)
    }

    pub fn control(
        &mut self,
        body: ControlRequest,
    ) -> Result<ResponseEnvelope<ControlResponse>> {
        let request_id = self.next_id();
        let env = RequestEnvelope { request_id, body };
        let payload = encode_payload(&env, self.limits.protocol())?;
        self.conn
            .write_frame(&build_frame(MessageType::ControlRequest, payload))?;
        let frame = self.conn.read_frame()?;
        decode_payload(&frame.payload)
    }

    pub fn data(&mut self, body: DataRequest) -> Result<ResponseEnvelope<DataResponse>> {
        let request_id = self.next_id();
        let env = RequestEnvelope { request_id, body };
        let payload = encode_payload(&env, self.limits.protocol())?;
        self.conn
            .write_frame(&build_frame(MessageType::DataRequest, payload))?;
        let frame = self.conn.read_frame()?;
        decode_payload(&frame.payload)
    }

    pub fn authenticate(
        &mut self,
        identity_name: &str,
        password: &str,
    ) -> Result<ResponseEnvelope<ControlResponse>> {
        self.control(ControlRequest::Authenticate {
            identity_name: identity_name.into(),
            password: password.into(),
        })
    }

    pub fn execute_sql(
        &mut self,
        session_id: &str,
        sql: &str,
    ) -> Result<ResponseEnvelope<DataResponse>> {
        self.data(DataRequest::ExecuteSql {
            session_id: session_id.into(),
            sql: sql.into(),
            params: Vec::new(),
        })
    }

    pub fn execute_sql_with_params(
        &mut self,
        session_id: &str,
        sql: &str,
        params: Vec<dmc_protocol::SqlParam>,
    ) -> Result<ResponseEnvelope<DataResponse>> {
        self.data(DataRequest::ExecuteSql {
            session_id: session_id.into(),
            sql: sql.into(),
            params,
        })
    }

    pub fn into_inner(self) -> C {
        self.conn.inner
    }
}

pub fn expect_ok_control(resp: ResponseEnvelope<ControlResponse>) -> Result<ControlResponse> {
    if resp.status == ResponseStatus::Ok {
        resp.body.ok_or_else(|| {
            ProtocolError::wire(ProtocolErrorCode::InternalError, "empty control body")
        })
    } else {
        Err(ProtocolError::wire(
            resp.error_code.unwrap_or(ProtocolErrorCode::InternalError),
            resp.error_message.unwrap_or_else(|| "control error".into()),
        ))
    }
}

pub fn expect_ok_data(resp: ResponseEnvelope<DataResponse>) -> Result<DataResponse> {
    if resp.status == ResponseStatus::Ok {
        resp.body.ok_or_else(|| {
            ProtocolError::wire(ProtocolErrorCode::InternalError, "empty data body")
        })
    } else {
        Err(ProtocolError::wire(
            resp.error_code.unwrap_or(ProtocolErrorCode::InternalError),
            resp.error_message.unwrap_or_else(|| "data error".into()),
        ))
    }
}
