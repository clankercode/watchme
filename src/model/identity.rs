use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

pub const PROCESS_IDENTITY_SCHEMA_VERSION: u16 = 1;
pub const TARGET_IDENTITY_SCHEMA_VERSION: u16 = 2;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum MultiplexerContext {
    Tmux {
        socket_path: String,
        server_instance: String,
        session_id: String,
        window_id: String,
        pane_id: String,
        tty: String,
    },
    Herdr {
        socket_path: String,
        server_instance: String,
        workspace_id: String,
        tab_id: String,
        pane_id: String,
        tty: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    schema_version: u16,
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

impl ProcessIdentity {
    pub const fn new(pid: u32, start_time: u64) -> Self {
        Self {
            schema_version: PROCESS_IDENTITY_SCHEMA_VERSION,
            pid,
            start_time,
            executable: None,
            argv_digest: None,
            uid: None,
            process_group_id: None,
            session_leader_id: None,
            tty: None,
            parent_digest: None,
        }
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }
}

impl<'de> Deserialize<'de> for ProcessIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SerializedIdentity {
            schema_version: u16,
            pid: u32,
            start_time: u64,
            executable: Option<String>,
            argv_digest: Option<String>,
            uid: Option<u32>,
            process_group_id: Option<u32>,
            session_leader_id: Option<u32>,
            tty: Option<String>,
            parent_digest: Option<String>,
        }

        let serialized = SerializedIdentity::deserialize(deserializer)?;
        if serialized.schema_version != PROCESS_IDENTITY_SCHEMA_VERSION {
            return Err(D::Error::custom(format_args!(
                "unsupported process identity schema version {}",
                serialized.schema_version
            )));
        }
        Ok(Self {
            schema_version: serialized.schema_version,
            pid: serialized.pid,
            start_time: serialized.start_time,
            executable: serialized.executable,
            argv_digest: serialized.argv_digest,
            uid: serialized.uid,
            process_group_id: serialized.process_group_id,
            session_leader_id: serialized.session_leader_id,
            tty: serialized.tty,
            parent_digest: serialized.parent_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetIdentity {
    Process {
        process: ProcessIdentity,
    },
    Multiplexer {
        provider: String,
        server: String,
        pane: String,
        process: ProcessIdentity,
        session: Option<String>,
        context: Option<Box<MultiplexerContext>>,
        chrome: Option<crate::observe::screen::TmuxChrome>,
        needs_revalidation: bool,
    },
}

impl TargetIdentity {
    pub const fn process(process: ProcessIdentity) -> Self {
        Self::Process { process }
    }

    pub fn multiplexer(
        provider: String,
        server: String,
        pane: String,
        process: ProcessIdentity,
        session: Option<String>,
    ) -> Self {
        Self::Multiplexer {
            provider,
            server,
            pane,
            process,
            session,
            context: None,
            chrome: None,
            needs_revalidation: true,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn tmux(
        socket_path: String,
        server_instance: String,
        session_id: String,
        window_id: String,
        pane_id: String,
        tty: String,
        process: ProcessIdentity,
        chrome: Option<crate::observe::screen::TmuxChrome>,
    ) -> Self {
        Self::Multiplexer {
            provider: "tmux".into(),
            server: socket_path.clone(),
            pane: pane_id.clone(),
            process,
            session: Some(session_id.clone()),
            context: Some(Box::new(MultiplexerContext::Tmux {
                socket_path,
                server_instance,
                session_id,
                window_id,
                pane_id,
                tty,
            })),
            chrome,
            needs_revalidation: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn herdr(
        socket_path: String,
        server_instance: String,
        workspace_id: String,
        tab_id: String,
        pane_id: String,
        tty: String,
        process: ProcessIdentity,
    ) -> Self {
        Self::Multiplexer {
            provider: "herdr".into(),
            server: socket_path.clone(),
            pane: pane_id.clone(),
            process,
            session: Some(workspace_id.clone()),
            context: Some(Box::new(MultiplexerContext::Herdr {
                socket_path,
                server_instance,
                workspace_id,
                tab_id,
                pane_id,
                tty,
            })),
            chrome: None,
            needs_revalidation: false,
        }
    }
    pub const fn needs_revalidation(&self) -> bool {
        matches!(
            self,
            Self::Multiplexer {
                needs_revalidation: true,
                ..
            }
        )
    }
    pub fn observation_context(&self) -> Option<&MultiplexerContext> {
        match self {
            Self::Multiplexer { context, .. } => context.as_deref(),
            _ => None,
        }
    }

    pub const fn schema_version(&self) -> u16 {
        TARGET_IDENTITY_SCHEMA_VERSION
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TargetWire {
    Process {
        schema_version: u16,
        process: ProcessIdentity,
    },
    Multiplexer {
        schema_version: u16,
        provider: String,
        server: String,
        pane: String,
        process: ProcessIdentity,
        session: Option<String>,
        #[serde(default)]
        context: Option<Box<MultiplexerContext>>,
        #[serde(default)]
        chrome: Option<crate::observe::screen::TmuxChrome>,
        #[serde(default)]
        needs_revalidation: bool,
    },
}

impl Serialize for TargetIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let wire = match self {
            Self::Process { process } => TargetWire::Process {
                schema_version: TARGET_IDENTITY_SCHEMA_VERSION,
                process: process.clone(),
            },
            Self::Multiplexer {
                provider,
                server,
                pane,
                process,
                session,
                context,
                chrome,
                needs_revalidation,
                ..
            } => TargetWire::Multiplexer {
                schema_version: TARGET_IDENTITY_SCHEMA_VERSION,
                provider: provider.clone(),
                server: server.clone(),
                pane: pane.clone(),
                process: process.clone(),
                session: session.clone(),
                context: context.clone(),
                chrome: chrome.clone(),
                needs_revalidation: *needs_revalidation,
            },
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TargetIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TargetWire::deserialize(deserializer)?;
        let version = match &wire {
            TargetWire::Process { schema_version, .. }
            | TargetWire::Multiplexer { schema_version, .. } => *schema_version,
        };
        if version != 1 && version != TARGET_IDENTITY_SCHEMA_VERSION {
            return Err(D::Error::custom(format_args!(
                "unsupported target identity schema version {version}"
            )));
        }
        Ok(match wire {
            TargetWire::Process { process, .. } => Self::Process { process },
            TargetWire::Multiplexer {
                provider,
                server,
                pane,
                process,
                session,
                context,
                chrome,
                needs_revalidation,
                ..
            } => Self::Multiplexer {
                provider,
                server,
                pane,
                process,
                session,
                context,
                chrome,
                needs_revalidation: version == 1 || needs_revalidation,
            },
        })
    }
}
