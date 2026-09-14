use serde::{Deserialize, Serialize};

/// Last catalog event sequence applied to materialized catalog state.
/// Separate domain from subscription offset, group offset, or journal head.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CatalogWatermark {
    pub sequence: u64,
}

impl CatalogWatermark {
    pub const fn at(sequence: u64) -> Self {
        Self { sequence }
    }
}

/// Last journal sequence applied to materialized catalog + row state.
/// Separate from subscription offset, group offset, and journal head.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MaterializedWatermark {
    pub sequence: u64,
}

impl MaterializedWatermark {
    pub const fn at(sequence: u64) -> Self {
        Self { sequence }
    }
}
