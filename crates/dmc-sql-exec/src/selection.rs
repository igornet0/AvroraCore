/// Sparse row selection — avoids copying unselected rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionVector {
    indices: Vec<usize>,
}

impl SelectionVector {
    pub fn identity(len: usize) -> Self {
        Self {
            indices: (0..len).collect(),
        }
    }

    pub fn from_mask(mask: &[bool]) -> Self {
        Self {
            indices: mask
                .iter()
                .enumerate()
                .filter_map(|(idx, keep)| (*keep).then_some(idx))
                .collect(),
        }
    }

    pub fn from_indices(indices: Vec<usize>) -> Self {
        Self { indices }
    }

    pub fn len(&self) -> usize {
        self.indices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    pub fn indices(&self) -> &[usize] {
        &self.indices
    }

    pub fn map_indices<T: Clone>(&self, source: &[T]) -> Vec<T> {
        self.indices
            .iter()
            .map(|&idx| source[idx].clone())
            .collect()
    }
}
