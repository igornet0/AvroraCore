use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use dmc_security::SessionId;

macro_rules! id_newtype {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4().to_string())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_string())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }
    };
}

id_newtype!(StreamId);
id_newtype!(ChannelId);
id_newtype!(TriggerId);
id_newtype!(SubsystemId);
id_newtype!(SubscriptionId);
id_newtype!(ConsumerId);
id_newtype!(DlqEntryId);

/// Client-provided consumer group identifier (Phase 5.8).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupId(pub String);

impl GroupId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for GroupId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for GroupId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Client-provided member identifier within a group (Phase 5.8).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MemberId(pub String);

impl MemberId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for MemberId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for MemberId {
    fn from(value: String) -> Self {
        Self(value)
    }
}
