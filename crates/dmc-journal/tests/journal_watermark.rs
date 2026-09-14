//! Phase 5.1 watermark aggregation tests.

use dmc_journal::{calculate_watermark, JournalPin, RetentionWatermark, SequencePin};

struct Pin(u64);

impl JournalPin for Pin {
    fn sequence(&self) -> u64 {
        self.0
    }
}

fn wm(pins: &[&dyn JournalPin]) -> RetentionWatermark {
    calculate_watermark(pins.iter().copied())
}

#[test]
fn basic_min_of_three() {
    let a = Pin(100);
    let b = Pin(200);
    let c = Pin(300);
    assert_eq!(wm(&[&a, &b, &c]).trim_through, Some(100));
}

#[test]
fn one_pin_moves() {
    let a = Pin(150);
    let b = Pin(200);
    let c = Pin(300);
    assert_eq!(wm(&[&a, &b, &c]).trim_through, Some(150));
}

#[test]
fn pin_disappears_raises_watermark() {
    let b = Pin(200);
    assert_eq!(wm(&[&b]).trim_through, Some(200));
}

#[test]
fn no_pins_is_none() {
    assert_eq!(wm(&[]).trim_through, None);
}

#[test]
fn snapshot_and_consumer() {
    let snapshot = Pin(1000);
    let consumer = Pin(700);
    assert_eq!(wm(&[&snapshot, &consumer]).trim_through, Some(700));
}

#[test]
fn replay_lowers_watermark() {
    let snapshot = Pin(1000);
    let consumer = Pin(900);
    let replay = Pin(400);
    assert_eq!(wm(&[&snapshot, &consumer, &replay]).trim_through, Some(400));
}

#[test]
fn replay_expiration_simulated_by_omitting_pin() {
    let snapshot = Pin(1000);
    let consumer = Pin(900);
    let with_replay = Pin(400);
    assert_eq!(
        wm(&[&snapshot, &consumer, &with_replay]).trim_through,
        Some(400)
    );
    assert_eq!(wm(&[&snapshot, &consumer]).trim_through, Some(900));
}

#[test]
fn sequence_pin_helper() {
    let p = SequencePin(42);
    assert_eq!(wm(&[&p]).trim_through, Some(42));
}

#[test]
fn journal_trim_noop_when_nothing_eligible() {
    let dir = tempfile::tempdir().unwrap();
    use dmc_journal::{Journal, JournalConfig};
    use dmc_vault::crypto::derive_journal_kek;
    use dmc_vault::key::{KeyPath, KeyTree};

    let (mut tree, master) = KeyTree::create_new().unwrap();
    let path = KeyPath::parse("company/a").unwrap();
    tree.ensure_node(&path).unwrap();
    let kek = derive_journal_kek(&master, tree.salt());
    let mut journal =
        Journal::open(JournalConfig::new(dir.path().join("journal")), &kek).unwrap();
    let result = journal.trim_through(0).unwrap();
    assert!(result.deleted_segments.is_empty());
}

#[test]
fn journal_retention_watermark_delegates() {
    let dir = tempfile::tempdir().unwrap();
    use dmc_journal::{Journal, JournalConfig};
    use dmc_vault::crypto::derive_journal_kek;
    use dmc_vault::key::{KeyPath, KeyTree};

    let (mut tree, master) = KeyTree::create_new().unwrap();
    let path = KeyPath::parse("company/a").unwrap();
    tree.ensure_node(&path).unwrap();
    let kek = derive_journal_kek(&master, tree.salt());
    let journal = Journal::open(JournalConfig::new(dir.path().join("journal")), &kek).unwrap();
    let a = Pin(100);
    let b = Pin(250);
    assert_eq!(
        journal.retention_watermark(&[&a, &b]).trim_through,
        Some(100)
    );
}
