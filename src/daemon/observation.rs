pub fn classify_herdr_state(
    state: &str,
    terminal_evidence: bool,
) -> Option<(crate::model::EventCategory, bool)> {
    use crate::model::EventCategory;
    match (state, terminal_evidence) {
        ("working", _) => Some((EventCategory::Working, false)),
        ("idle", _) => Some((EventCategory::Idle, false)),
        ("waiting", _) => Some((EventCategory::WaitingForTool, false)),
        ("terminated", true) => Some((EventCategory::Terminated, true)),
        ("blocked", true) => Some((EventCategory::BlockedGoal, true)),
        _ => None,
    }
}

pub(super) fn observation_event(
    watcher: &crate::model::WatcherState,
    kind: crate::model::SourceKind,
    source: &str,
    rule: &str,
    category: crate::model::EventCategory,
    confidence: f64,
    evidence: &[u8],
) -> Result<crate::model::Event, String> {
    use sha2::{Digest, Sha256};
    let target_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&watcher.target).map_err(|error| error.to_string())?)
    );
    let observed: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    crate::model::Event::new(
        format!("obs-{}-{}", watcher.watcher_id, watcher.revision),
        observed.to_rfc3339(),
        watcher.watcher_id.clone(),
        target_hash,
        crate::model::EventSource::new(kind, source, rule),
        category,
        confidence,
        false,
        crate::observe::evidence_fingerprint(source, rule, evidence),
        "bounded observation",
        crate::model::PolicyHint::ObserveOnly,
    )
    .map_err(|error| error.to_string())
}
