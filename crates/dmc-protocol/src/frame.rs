use crate::error::{ProtocolError, Result};
use crate::limits::ProtocolLimits;
use crate::PROTOCOL_VERSION;

pub const HEADER_SIZE: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u16,
    pub message_type: MessageType,
    pub payload_len: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    HandshakeRequest = 1,
    HandshakeResponse = 2,
    ControlRequest = 3,
    ControlResponse = 4,
    DataRequest = 5,
    DataResponse = 6,
}

impl MessageType {
    pub fn from_u16(raw: u16) -> Result<Self> {
        match raw {
            1 => Ok(Self::HandshakeRequest),
            2 => Ok(Self::HandshakeResponse),
            3 => Ok(Self::ControlRequest),
            4 => Ok(Self::ControlResponse),
            5 => Ok(Self::DataRequest),
            6 => Ok(Self::DataResponse),
            other => Err(ProtocolError::UnknownMessageType(other)),
        }
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

pub fn encode_frame(frame: &Frame, limits: &ProtocolLimits) -> Result<Vec<u8>> {
    if frame.header.version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(frame.header.version));
    }
    if frame.payload.len() as u32 > limits.max_frame_size {
        return Err(ProtocolError::FrameTooLarge(frame.payload.len() as u32));
    }
    if frame.header.payload_len as usize != frame.payload.len() {
        return Err(ProtocolError::InvalidFrame(
            "payload length mismatch".into(),
        ));
    }
    let mut out = Vec::with_capacity(HEADER_SIZE + frame.payload.len());
    out.extend_from_slice(&frame.header.version.to_le_bytes());
    out.extend_from_slice(&frame.header.message_type.as_u16().to_le_bytes());
    out.extend_from_slice(&frame.header.payload_len.to_le_bytes());
    out.extend_from_slice(&frame.payload);
    Ok(out)
}

pub fn decode_frame(bytes: &[u8], limits: &ProtocolLimits) -> Result<Frame> {
    if bytes.len() < HEADER_SIZE {
        return Err(ProtocolError::InvalidFrame("truncated header".into()));
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let message_type = MessageType::from_u16(u16::from_le_bytes([bytes[2], bytes[3]]))?;
    let payload_len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if payload_len > limits.max_frame_size {
        return Err(ProtocolError::FrameTooLarge(payload_len));
    }
    let total = HEADER_SIZE + payload_len as usize;
    if bytes.len() < total {
        return Err(ProtocolError::InvalidFrame("truncated payload".into()));
    }
    if bytes.len() > total {
        return Err(ProtocolError::InvalidFrame("trailing bytes".into()));
    }
    Ok(Frame {
        header: FrameHeader {
            version,
            message_type,
            payload_len,
        },
        payload: bytes[HEADER_SIZE..total].to_vec(),
    })
}
