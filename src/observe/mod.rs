pub mod jsonl;
pub mod screen;

use std::collections::BTreeMap;

use crate::model::{Event, EventCategory};
use sha2::{Digest, Sha256};

pub fn evidence_fingerprint(source: &str, rule: &str, evidence: &[u8]) -> String {
    let mut hash = Sha256::new();
    for part in [source.as_bytes(), rule.as_bytes(), evidence] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    format!("{:x}", hash.finalize())
}

#[derive(Default)]
pub struct EvidenceMerger;
impl EvidenceMerger {
    pub fn select_actionable<'a>(&self, events: &'a [Event]) -> Option<&'a Event> {
        let candidate = events
            .iter()
            .filter(|e| e.category.is_actionable())
            .max_by(|a, b| {
                a.source
                    .kind
                    .rank()
                    .cmp(&b.source.kind.rank())
                    .then_with(|| a.confidence.total_cmp(&b.confidence))
            });
        let candidate = candidate?;
        if events.iter().any(|other| {
            correlated(other, candidate)
                && contradicts(other.category, candidate.category)
                && (other.source.kind.rank() > candidate.source.kind.rank()
                    || (other.source.kind.rank() == candidate.source.kind.rank()
                        && other.confidence >= candidate.confidence))
        }) {
            None
        } else {
            Some(candidate)
        }
    }
}
fn correlated(left: &Event, right: &Event) -> bool {
    left.watcher_id == right.watcher_id
        && left.target_identity_hash == right.target_identity_hash
        && (left.session_id.is_none()
            || right.session_id.is_none()
            || left.session_id == right.session_id)
}
fn contradicts(a: EventCategory, b: EventCategory) -> bool {
    a != b
        && matches!(
            a,
            EventCategory::Working
                | EventCategory::Idle
                | EventCategory::Recovered
                | EventCategory::HumanIntervention
        )
}

/// Deterministic per-target cadence. Callers supply a bounded jitter chosen at
/// registration so the core does not depend on ambient randomness or clocks.
pub struct ObservationCadence {
    interval_seconds: u64,
    max_jitter_seconds: u64,
    next_due: BTreeMap<String, u64>,
}

impl ObservationCadence {
    pub fn new(interval_seconds: u64, max_jitter_seconds: u64) -> Self {
        Self {
            interval_seconds: interval_seconds.max(1),
            max_jitter_seconds,
            next_due: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, target: impl Into<String>, now: u64, jitter_seconds: u64) {
        self.next_due.insert(
            target.into(),
            now.saturating_add(self.interval_seconds)
                .saturating_add(jitter_seconds.min(self.max_jitter_seconds)),
        );
    }

    pub fn wake(&mut self, target: &str) {
        if let Some(next_due) = self.next_due.get_mut(target) {
            *next_due = 0;
        }
    }

    pub fn due(&mut self, now: u64) -> Vec<String> {
        let due: Vec<_> = self
            .next_due
            .iter()
            .filter(|(_, next_due)| **next_due <= now)
            .map(|(target, _)| target.clone())
            .collect();
        for target in &due {
            self.next_due
                .insert(target.clone(), now.saturating_add(self.interval_seconds));
        }
        due
    }
}
