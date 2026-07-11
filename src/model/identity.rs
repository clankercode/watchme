use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time: u64,
    pub executable: Option<String>,
    pub argv_digest: Option<String>,
    pub uid: Option<u32>,
    pub process_group_id: Option<u32>,
    pub session_leader_id: Option<u32>,
    pub tty: Option<String>,
    pub parent_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetIdentity {
    Process {
        version: u16,
        process: ProcessIdentity,
    },
    Multiplexer {
        version: u16,
        provider: String,
        server: String,
        pane: String,
        process: ProcessIdentity,
        session: Option<String>,
    },
}
