use crate::error::{ProtocolError, Result};
use crate::limits::ProtocolLimits;

pub fn encode_payload<T: serde::Serialize>(value: &T, limits: &ProtocolLimits) -> Result<Vec<u8>> {
    let payload = postcard::to_allocvec(value)?;
    if payload.len() as u32 > limits.max_frame_size {
        return Err(ProtocolError::FrameTooLarge(payload.len() as u32));
    }
    Ok(payload)
}

pub fn decode_payload<T: serde::de::DeserializeOwned>(payload: &[u8]) -> Result<T> {
    Ok(postcard::from_bytes(payload)?)
}
