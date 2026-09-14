/// Column validity bitmap — `false` means SQL NULL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidityBitmap {
    bits: Vec<bool>,
}

impl ValidityBitmap {
    pub fn all_valid(len: usize) -> Self {
        Self {
            bits: vec![true; len],
        }
    }

    pub fn all_null(len: usize) -> Self {
        Self {
            bits: vec![false; len],
        }
    }

    pub fn from_bits(bits: Vec<bool>) -> Self {
        Self { bits }
    }

    pub fn len(&self) -> usize {
        self.bits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    pub fn is_valid(&self, idx: usize) -> bool {
        self.bits.get(idx).copied().unwrap_or(false)
    }

    pub fn set_valid(&mut self, idx: usize, valid: bool) {
        if let Some(bit) = self.bits.get_mut(idx) {
            *bit = valid;
        }
    }

    pub fn bits(&self) -> &[bool] {
        &self.bits
    }

    pub fn select(&self, indices: &[usize]) -> Self {
        Self {
            bits: indices
                .iter()
                .map(|&idx| self.is_valid(idx))
                .collect(),
        }
    }

    pub fn extend(&mut self, other: &Self) {
        self.bits.extend(other.bits.iter().copied());
    }
}
