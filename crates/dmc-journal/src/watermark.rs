//! Retention watermark: aggregate pins without knowing their origin.
//!
//! Phase 5.1: compute only. Physical segment delete is disabled until manifest + GC (5.2–5.3).

/// A lower bound on how far journal prefix trim may advance.
///
/// `sequence` is the last journal sequence that **may be deleted** (inclusive).
/// Sequences `sequence + 1 .. HEAD` must remain readable.
pub trait JournalPin {
    fn sequence(&self) -> u64;
}

/// Result of pin aggregation. No pins → `trim_through == None` (trim unsafe).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionWatermark {
    pub trim_through: Option<u64>,
}

impl RetentionWatermark {
    pub fn none() -> Self {
        Self { trim_through: None }
    }

    pub fn is_trim_allowed(&self) -> bool {
        self.trim_through.is_some()
    }
}

/// `trim_through = min(pin sequences)`. Empty iterator → `None`.
pub fn calculate_watermark<'a>(pins: impl IntoIterator<Item = &'a dyn JournalPin>) -> RetentionWatermark {
    let mut min: Option<u64> = None;
    for pin in pins {
        let seq = pin.sequence();
        min = Some(match min {
            Some(m) => m.min(seq),
            None => seq,
        });
    }
    RetentionWatermark { trim_through: min }
}

/// Test / policy helper: fixed trim floor without runtime semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequencePin(pub u64);

impl JournalPin for SequencePin {
    fn sequence(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn empty_pins_none() {
        let w = calculate_watermark(std::iter::empty::<&dyn JournalPin>());
        assert_eq!(w.trim_through, None);
    }

    #[test]
    fn single_pin() {
        let p = SequencePin(500);
        let w = calculate_watermark([&p as &dyn JournalPin]);
        assert_eq!(w.trim_through, Some(500));
    }
}
