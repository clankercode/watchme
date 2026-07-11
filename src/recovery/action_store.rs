use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::recovery::transaction::{ActionRecord, ActionStore};
use crate::store::{JsonStore, LoadOutcome};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u16,
    audit: BTreeMap<String, Vec<ActionRecord>>,
    active: BTreeMap<String, ActionRecord>,
    idempotency: BTreeSet<String>,
}

struct DurableLedger {
    store: JsonStore,
    state: Ledger,
}

/// Owner-private JSON ledger. The mutex makes claim plus persistence one CAS
/// boundary for all daemon tasks; JsonStore provides fsync plus atomic rename.
pub struct JsonActionStore(Mutex<DurableLedger>);

impl JsonActionStore {
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let store = JsonStore::new(path);
        let state = match store.load::<Ledger>().map_err(|error| error.to_string())? {
            LoadOutcome::Missing => Ledger {
                version: 1,
                ..Ledger::default()
            },
            LoadOutcome::Present(state) if state.version == 1 => state,
            LoadOutcome::Present(_) => return Err("unsupported action ledger version".into()),
            LoadOutcome::Corrupt { quarantine } => {
                return Err(format!(
                    "corrupt action ledger quarantined at {}",
                    quarantine.display()
                ));
            }
        };
        Ok(Self(Mutex::new(DurableLedger { store, state })))
    }
}

impl ActionStore for JsonActionStore {
    fn claim_prepared(&self, target: &str, record: ActionRecord) -> Result<bool, String> {
        let mut ledger = self.0.lock().map_err(|_| "action ledger lock poisoned")?;
        if ledger.state.active.contains_key(target)
            || ledger.state.idempotency.contains(&record.idempotency_key)
        {
            return Ok(false);
        }
        let mut next = ledger.state.clone();
        next.idempotency.insert(record.idempotency_key.clone());
        next.active.insert(target.into(), record.clone());
        next.audit.entry(target.into()).or_default().push(record);
        ledger
            .store
            .write(&next)
            .map_err(|error| error.to_string())?;
        ledger.state = next;
        Ok(true)
    }

    fn append(&self, target: &str, record: ActionRecord) -> Result<(), String> {
        let mut ledger = self.0.lock().map_err(|_| "action ledger lock poisoned")?;
        let current = ledger
            .state
            .active
            .get(target)
            .ok_or("target has no active transaction")?;
        if current.idempotency_key != record.idempotency_key
            || current.action_id != record.action_id
        {
            return Err("action transaction CAS mismatch".into());
        }
        let mut next = ledger.state.clone();
        next.audit
            .entry(target.into())
            .or_default()
            .push(record.clone());
        if record.phase.is_terminal() {
            next.active.remove(target);
        } else {
            next.active.insert(target.into(), record);
        }
        ledger
            .store
            .write(&next)
            .map_err(|error| error.to_string())?;
        ledger.state = next;
        Ok(())
    }

    fn active(&self, target: &str) -> Result<Option<ActionRecord>, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "action ledger lock poisoned")?
            .state
            .active
            .get(target)
            .cloned())
    }

    fn audit(&self, target: &str) -> Result<Vec<ActionRecord>, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "action ledger lock poisoned")?
            .state
            .audit
            .get(target)
            .cloned()
            .unwrap_or_default())
    }
}
