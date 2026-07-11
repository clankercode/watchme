//! Concrete observation runtime for supported process and multiplexer targets.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::{now_ms, observation_event};

pub trait Observer: Send + Sync + 'static {
    fn observe<'a>(
        &'a self,
        watcher: crate::model::WatcherState,
    ) -> Pin<Box<dyn Future<Output = Result<ObservationResult, String>> + Send + 'a>>;
}

#[derive(Default)]
pub struct ObservationResult {
    pub event: Option<crate::model::Event>,
    pub herdr_after_sequence: Option<u64>,
}

pub trait ObservationClock: Send + Sync + 'static {
    fn wall_now_ms(&self) -> u64;
    fn mono_now_ms(&self) -> u64;
    fn sleep_until_mono<'a>(
        &'a self,
        deadline: u64,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

pub(super) struct SystemObservationClock {
    origin: std::time::Instant,
}

impl SystemObservationClock {
    pub(super) fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

impl ObservationClock for SystemObservationClock {
    fn wall_now_ms(&self) -> u64 {
        now_ms()
    }

    fn mono_now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    fn sleep_until_mono<'a>(
        &'a self,
        deadline: u64,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(tokio::time::sleep(Duration::from_millis(
            deadline.saturating_sub(self.mono_now_ms()),
        )))
    }
}

pub struct GenericObserver;

impl Observer for GenericObserver {
    fn observe<'a>(
        &'a self,
        watcher: crate::model::WatcherState,
    ) -> Pin<Box<dyn Future<Output = Result<ObservationResult, String>> + Send + 'a>> {
        Box::pin(async move {
            let now: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
            if crate::agents::claude::resume_candidate_event(&watcher, now).is_some()
                && tokio::task::spawn_blocking({
                    let watcher = watcher.clone();
                    move || crate::agents::claude::correlated_hook_event(&watcher).is_some()
                })
                .await
                .map_err(|error| error.to_string())?
            {
                return Ok(ObservationResult {
                    event: crate::agents::claude::resume_candidate_event(&watcher, now),
                    herdr_after_sequence: None,
                });
            }
            if let Some(event) = tokio::task::spawn_blocking({
                let watcher = watcher.clone();
                move || crate::agents::claude::correlated_hook_event(&watcher)
            })
            .await
            .map_err(|error| error.to_string())?
            {
                return Ok(ObservationResult {
                    event: Some(event),
                    herdr_after_sequence: None,
                });
            }
            if let crate::model::TargetIdentity::Multiplexer {
                context: Some(context),
                process,
                ..
            } = &watcher.target
                && let crate::model::MultiplexerContext::Herdr {
                    socket_path,
                    workspace_id,
                    tab_id,
                    pane_id,
                    ..
                } = context.as_ref()
            {
                return observe_herdr(
                    &watcher,
                    process,
                    socket_path,
                    workspace_id,
                    tab_id,
                    pane_id,
                )
                .await;
            }
            tokio::task::spawn_blocking(move || generic_observe(&watcher))
                .await
                .map_err(|error| error.to_string())?
        })
    }
}

async fn observe_herdr(
    watcher: &crate::model::WatcherState,
    process: &crate::model::ProcessIdentity,
    socket_path: &str,
    workspace_id: &str,
    tab_id: &str,
    pane_id: &str,
) -> Result<ObservationResult, String> {
    let context = crate::mux::herdr::HerdrContext {
        socket_path: socket_path.to_owned(),
        workspace_id: workspace_id.to_owned(),
        tab_id: tab_id.to_owned(),
        pane_id: pane_id.to_owned(),
    };
    let herdr = crate::mux::herdr::Herdr::new(context, Duration::from_secs(2))
        .map_err(|error| error.to_string())?;
    let actual = herdr
        .current_target_async()
        .await
        .map_err(|error| error.to_string())?;
    if actual.process.pid != process.pid || actual.process.start_time != process.start_time {
        return Err("target identity changed".into());
    }
    let state = herdr
        .agent_state_events_async(
            &actual,
            watcher.observation_schedule.herdr_after_sequence,
            64,
        )
        .await
        .map_err(|error| error.to_string())?;
    let evidence = if state.events.is_empty() {
        let capture = herdr
            .capture_tail_async(&actual, 80, 32 * 1024)
            .await
            .map_err(|error| error.to_string())?;
        crate::observe::screen::sanitize_terminal(capture.text.as_bytes(), 32 * 1024, 80)
            .into_bytes()
    } else {
        serde_json::to_vec(&state).map_err(|error| error.to_string())?
    };
    let terminal_evidence = state.events.iter().any(|event| event.kind == "terminal");
    let classification = (!state.events.is_empty())
        .then(|| super::classify_herdr_state(&state.state, terminal_evidence))
        .flatten();
    let cursor = state.events.iter().map(|event| event.sequence).max();
    let Some((category, terminal)) = classification else {
        return Ok(ObservationResult {
            event: None,
            herdr_after_sequence: cursor,
        });
    };
    let mut event = observation_event(
        watcher,
        crate::model::SourceKind::HerdrAgentState,
        "herdr",
        "typed_pane_state",
        category,
        0.8,
        &evidence,
    )?;
    event.terminal = terminal;
    event.monotonic_sequence = cursor;
    Ok(ObservationResult {
        event: Some(event),
        herdr_after_sequence: cursor,
    })
}

fn generic_observe(watcher: &crate::model::WatcherState) -> Result<ObservationResult, String> {
    use crate::mux::Multiplexer;

    if let crate::model::TargetIdentity::Process { process } = &watcher.target {
        use crate::process::ProcessInspector;

        #[cfg(target_os = "linux")]
        let inspector = crate::process::linux::LinuxProcessInspector::default();
        #[cfg(target_os = "macos")]
        let inspector = crate::process::macos::MacOsProcessInspector::default();
        let alive = inspector
            .inspect(process.pid)
            .ok()
            .is_some_and(|actual| actual.start_time == process.start_time);
        let category = if alive {
            crate::model::EventCategory::Working
        } else {
            crate::model::EventCategory::Terminated
        };
        return observation_event(
            watcher,
            crate::model::SourceKind::ProcessMetadata,
            "process",
            "liveness",
            category,
            1.0,
            if alive { b"alive" } else { b"dead" },
        )
        .map(|event| ObservationResult {
            event: Some(event),
            herdr_after_sequence: None,
        });
    }
    let crate::model::TargetIdentity::Multiplexer {
        provider,
        server,
        pane,
        process,
        session,
        context,
        chrome,
        ..
    } = &watcher.target
    else {
        return Ok(ObservationResult::default());
    };
    if provider != "tmux" || watcher.target.needs_revalidation() {
        return Ok(ObservationResult::default());
    }
    let Some(context) = context else {
        return Ok(ObservationResult::default());
    };
    let crate::model::MultiplexerContext::Tmux {
        socket_path,
        session_id,
        window_id,
        pane_id,
        tty,
        server_instance,
    } = context.as_ref()
    else {
        return Ok(ObservationResult::default());
    };
    let tmux = crate::mux::tmux::Tmux::for_socket_path(server.clone(), Duration::from_secs(2));
    let selector =
        crate::mux::tmux::TmuxSelector::parse(pane).map_err(|error| error.to_string())?;
    let identity = tmux
        .resolve_selector(&selector)
        .map_err(|error| error.to_string())?;
    if identity.process.pid != process.pid || identity.process.start_time != process.start_time {
        return Err("target identity changed".into());
    }
    if &identity.server != socket_path
        || &identity.server_instance != server_instance
        || &identity.session_id != session_id
        || &identity.window_id != window_id
        || &identity.pane_id != pane_id
        || &identity.tty != tty
    {
        return Err("target multiplexer identity changed".into());
    }
    let capture = tmux
        .capture_tail(&identity, 80, 32 * 1024)
        .map_err(|error| error.to_string())?;
    let clean = crate::observe::screen::sanitize_terminal(capture.text.as_bytes(), 32 * 1024, 80);
    let live = chrome.as_ref().map_or_else(
        || crate::observe::screen::LiveScreen::from_adapter(Vec::new(), None, false),
        |descriptor| crate::observe::screen::trusted_tmux_screen(&clean, descriptor),
    );
    let actionable = live.actionable_bottom(40);
    // A menu is an input-capable boundary only when two fresh trusted live
    // captures agree exactly. Generic tails remain observation-only.
    if let Some(first) = actionable.as_deref() {
        let second_capture = tmux
            .capture_tail(&identity, 80, 32 * 1024)
            .map_err(|error| error.to_string())?;
        let second_clean = crate::observe::screen::sanitize_terminal(
            second_capture.text.as_bytes(),
            32 * 1024,
            80,
        );
        let second_live = chrome.as_ref().map_or_else(
            || crate::observe::screen::LiveScreen::from_adapter(Vec::new(), None, false),
            |descriptor| crate::observe::screen::trusted_tmux_screen(&second_clean, descriptor),
        );
        if let Some(second) = second_live.actionable_bottom(40)
            && let Some(event) = crate::agents::claude::trusted_menu_event(watcher, first, &second)
        {
            return Ok(ObservationResult {
                event: Some(event),
                herdr_after_sequence: None,
            });
        }
    }
    let fingerprint =
        crate::observe::evidence_fingerprint("screen_detection", "generic_tail", clean.as_bytes());
    let target_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&watcher.target).map_err(|error| error.to_string())?)
    );
    let observed: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    if !clean.trim().is_empty() {
        return Ok(ObservationResult::default());
    }
    let category = crate::model::EventCategory::Idle;
    let mut event = crate::model::Event::new(
        format!("obs-{}-{}", watcher.watcher_id, watcher.revision),
        observed.to_rfc3339(),
        watcher.watcher_id.clone(),
        target_hash,
        crate::model::EventSource::new(
            crate::model::SourceKind::ScreenDetection,
            "tmux",
            "generic_tail",
        ),
        category,
        if actionable.is_some() { 0.4 } else { 0.2 },
        false,
        fingerprint,
        "bounded generic observation",
        crate::model::PolicyHint::ObserveOnly,
    )
    .map_err(|error| error.to_string())?;
    event.session_id = session.clone();
    Ok(ObservationResult {
        event: Some(event),
        herdr_after_sequence: None,
    })
}
