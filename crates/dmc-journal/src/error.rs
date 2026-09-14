use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("journal io: {0}")]
    Io(String),
    #[error("journal format: {0}")]
    Format(String),
    #[error("journal crypto: {0}")]
    Crypto(String),
    #[error(transparent)]
    Vault(#[from] dmc_vault::Error),

    #[error("trim beyond watermark: requested {requested}, max safe {watermark}")]
    TrimBeyondWatermark { requested: u64, watermark: u64 },

    #[error("trim unsafe: no retention watermark")]
    TrimUnsafe,

    #[error("snapshot unavailable: {0}")]
    SnapshotUnavailable(String),

    #[error("snapshot corrupt: {0}")]
    SnapshotCorrupt(String),

    #[error("snapshot inconsistent with journal: {0}")]
    SnapshotInconsistent(String),

    #[error("compaction not implemented")]
    CompactionNotImplemented,

    #[error("journal topology mutation already active")]
    TopologyMutationActive,

    #[error("journal manifest inconsistent: {0}")]
    JournalManifestInconsistent(String),

    #[error("journal segment corrupt: {0}")]
    JournalSegmentCorrupt(String),

    #[error("journal sequence conflict: {0}")]
    JournalSequenceConflict(String),

    #[error("compaction candidate stale")]
    CompactionStaleCandidate,
}

impl Error {
    pub fn io(err: impl std::fmt::Display) -> Self {
        Self::Io(err.to_string())
    }

    pub fn format(err: impl std::fmt::Display) -> Self {
        Self::Format(err.to_string())
    }
}
