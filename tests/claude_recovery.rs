use std::fs;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use chrono::{Datelike, FixedOffset, TimeZone, Timelike};
use tempfile::tempdir;
use watchme::agents::claude::{
    ClaudeClass, ClaudeRecipes, classify_screen, classify_stop_failure, correlated_hook_event,
    labelled_wait_menu, menu_keys, resume_candidate_event, trusted_menu_event,
    trusted_resume_progress_event,
};
use watchme::daemon::{GenericObserver, Observer};
use watchme::hooks::claude::{
    HookMarker, correlate_marker, install_stop_failure_hook, read_markers,
    remove_stop_failure_hook, write_marker,
};
use watchme::model::{
    ActionKind, ClaudeSessionReference, Event, EventCategory, EventSource, PolicyHint,
    ProcessIdentity, TargetIdentity, WatcherLifecycle, WatcherState,
};
use watchme::recovery::engine::RecipeProvider;
use watchme::recovery::reset_time::parse_reset;

#[test]
fn structured_failure_distinguishes_safe_and_unsafe_classes() {
    assert_eq!(
        classify_stop_failure("overloaded_error", "capacity unavailable", false),
        ClaudeClass::TerminalOverload
    );
    assert_eq!(
        classify_stop_failure("authentication_error", "sign in", false),
        ClaudeClass::HumanRequired
    );
    assert_eq!(
        classify_stop_failure(
            "rate_limit_error",
            "weekly usage limit resets Jul 14 at 5am (Australia/Sydney)",
            false
        ),
        ClaudeClass::WeeklyLimit
    );
    assert_eq!(
        classify_stop_failure("overloaded_error", "retrying in 5s", true),
        ClaudeClass::NativeRetry
    );
}

#[test]
fn resume_candidate_requires_wait_deadline_and_a_still_correlated_marker() {
    let mut watcher = claude_watcher(EventCategory::UsageLimit, PolicyHint::WaitAllowed, true);
    watcher.lifecycle = WatcherLifecycle::Waiting {
        until_unix_ms: 1,
        reason: "recovery wait scheduled".into(),
    };
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-12T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let reset = "2026-07-11T00:00:00Z";
    watcher.last_observation.as_mut().unwrap().metadata.insert(
        "claude_reset_at".into(),
        serde_json::Value::String(reset.into()),
    );
    watcher.last_observation.as_mut().unwrap().metadata.insert(
        "claude_resume_margin_seconds".into(),
        serde_json::Value::Number(0.into()),
    );
    let event = resume_candidate_event(&watcher, now).unwrap();
    assert_eq!(event.category, EventCategory::WaitingForModel);
    assert_eq!(event.metadata["claude_resume"], true);
    assert_eq!(event.metadata["agent_state"], "WORKING");
    watcher.lifecycle = WatcherLifecycle::Observing;
    assert!(resume_candidate_event(&watcher, now).is_none());
}

#[test]
fn resume_candidate_rearms_a_single_literal_resume_after_the_reset_margin() {
    let mut watcher = claude_watcher(EventCategory::UsageLimit, PolicyHint::WaitAllowed, true);
    watcher.lifecycle = WatcherLifecycle::Waiting {
        until_unix_ms: 1,
        reason: "recovery wait scheduled".into(),
    };
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-12T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let event = watcher.last_observation.as_mut().unwrap();
    event.metadata.insert(
        "claude_reset_at".into(),
        serde_json::Value::String("2026-07-11T00:00:00Z".into()),
    );
    event.metadata.insert(
        "claude_resume_margin_seconds".into(),
        serde_json::Value::Number(0.into()),
    );
    watcher.last_observation = Some(resume_candidate_event(&watcher, now).unwrap());
    assert_eq!(
        watcher.last_observation.as_ref().unwrap().policy_hint,
        PolicyHint::DeterministicActionAllowed
    );
    let action = ClaudeRecipes::default().action_for(&watcher).unwrap();
    assert_eq!(action.action_id, "claude.resume_once");
    assert_eq!(
        action.kind,
        ActionKind::SendText {
            text: "Continue exactly where you left off.".into()
        }
    );
}

#[test]
fn hook_marker_writer_is_append_only_and_rejects_unsafe_marker_paths() {
    let temp = tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let marker = temp.path().join("stop-failure.jsonl");
    let event = HookMarker {
        session_id: "session-1".into(),
        transcript_path: "/safe/session.jsonl".into(),
        error_type: "rate_limit_error".into(),
        detail: "resets in 10 minutes".into(),
    };
    write_marker(&marker, &event).unwrap();
    write_marker(&marker, &event).unwrap();
    assert_eq!(read_markers(&marker).unwrap().len(), 2);
    let link = temp.path().join("link.jsonl");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&marker, &link).unwrap();
    #[cfg(unix)]
    assert!(write_marker(&link, &event).is_err());
}

#[test]
fn live_screen_menu_uses_label_never_option_number_and_requires_stability() {
    let screen =
        "Choose an action\n  1. Add funds\n> 2. Stop and wait for limit to reset\n  3. Upgrade";
    let menu = labelled_wait_menu(screen, screen).expect("stable menu");
    assert_eq!(menu.moves, 0);
    assert_eq!(menu_keys(&menu), ["ENTER"]);
    assert_eq!(classify_screen(screen, screen), ClaudeClass::UsageLimit);
    assert!(labelled_wait_menu(screen, "Working... [stop]").is_none());
    assert!(
        labelled_wait_menu(
            "\"Stop and wait for limit to reset\"",
            "\"Stop and wait for limit to reset\""
        )
        .is_none()
    );
}

#[test]
fn trusted_menu_event_carries_only_symbolic_semantic_selection() {
    let mut watcher = claude_watcher(EventCategory::Idle, PolicyHint::ObserveOnly, false);
    let screen = "  1. Buy credits\n> 2. Stop and wait for limit to reset\n  3. Exit";
    let event = trusted_menu_event(&watcher, screen, screen).unwrap();
    assert_eq!(
        event.source.kind,
        watchme::model::SourceKind::ScreenDetection
    );
    assert_eq!(event.metadata["claude_menu_moves"], 0);
    watcher.last_observation = Some(event);
    let action = ClaudeRecipes::default().action_for(&watcher).unwrap();
    assert_eq!(
        action.kind,
        ActionKind::SendKeys {
            keys: vec!["ENTER".into()]
        }
    );
}

#[test]
fn reset_parser_handles_relative_and_sydney_wall_clock_without_guessing_status_time() {
    let now = FixedOffset::east_opt(10 * 3600)
        .unwrap()
        .with_ymd_and_hms(2026, 7, 11, 12, 0, 0)
        .unwrap();
    let relative = parse_reset("Resets in: 4 hours 23 minutes", now).expect("relative reset");
    assert_eq!(
        relative.at,
        now + chrono::Duration::hours(4) + chrono::Duration::minutes(23)
    );
    let wall = parse_reset("resets at 3:20 PM Australia/Sydney", now).expect("wall reset");
    assert!(wall.at > now);
    assert!(parse_reset("Current time 12:00", now).is_none());
}

#[test]
fn hook_merge_ingestion_and_remove_preserve_user_settings() {
    let temp = tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let settings = temp.path().join("settings.json");
    fs::write(
        &settings,
        r#"{"hooks":{"PreToolUse":[{"command":"keep"}]},"x":true}"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let marker = temp.path().join("markers.jsonl");
    assert!(install_stop_failure_hook(&settings, &marker).unwrap());
    assert!(!install_stop_failure_hook(&settings, &marker).unwrap());
    assert!(
        fs::read_to_string(&settings)
            .unwrap()
            .contains("PreToolUse")
    );
    let installed: serde_json::Value =
        serde_json::from_slice(&fs::read(&settings).unwrap()).unwrap();
    let group = &installed["hooks"]["StopFailure"][0];
    assert_eq!(group["matcher"], "rate_limit|overloaded|server_error");
    assert_eq!(group["hooks"].as_array().unwrap().len(), 1);
    assert_eq!(group["hooks"][0]["type"], "command");
    let command = group["hooks"][0]["command"].as_str().unwrap();
    assert_eq!(
        command,
        format!(
            "watchme watchme-hook-stop-failure --marker '{}'",
            marker.display()
        )
    );
    fs::write(
        &marker,
        serde_json::to_string(&HookMarker {
            session_id: "s".into(),
            transcript_path: "/safe/t.jsonl".into(),
            error_type: "overloaded_error".into(),
            detail: "temporary".into(),
        })
        .unwrap()
            + "\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(read_markers(&marker).unwrap().len(), 1);
    assert!(remove_stop_failure_hook(&settings, &marker).unwrap());
    assert!(
        fs::read_to_string(&settings)
            .unwrap()
            .contains("PreToolUse")
    );
}

#[test]
fn hook_lifecycle_preserves_other_stop_failure_matcher_groups() {
    let temp = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let settings = temp.path().join("settings.json");
    fs::write(
        &settings,
        r#"{"hooks":{"StopFailure":[{"matcher":"authentication_failed","hooks":[{"type":"command","command":"keep"}]}]}}"#,
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).unwrap();
    let marker = temp.path().join("markers.jsonl");
    assert!(install_stop_failure_hook(&settings, &marker).unwrap());
    let installed: serde_json::Value =
        serde_json::from_slice(&fs::read(&settings).unwrap()).unwrap();
    assert_eq!(
        installed["hooks"]["StopFailure"].as_array().unwrap().len(),
        2
    );
    assert!(remove_stop_failure_hook(&settings, &marker).unwrap());
    let removed: serde_json::Value = serde_json::from_slice(&fs::read(&settings).unwrap()).unwrap();
    assert_eq!(removed["hooks"]["StopFailure"].as_array().unwrap().len(), 1);
    assert_eq!(
        removed["hooks"]["StopFailure"][0]["matcher"],
        "authentication_failed"
    );
}

#[test]
fn transcript_binding_accepts_append_but_rejects_replacement() {
    let temp = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let transcript = temp.path().join("session.jsonl");
    fs::write(&transcript, "{\"sessionId\":\"s\"}\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    let canonical = fs::canonicalize(&transcript).unwrap();
    let binding = watchme::hooks::claude::bind_transcript(&canonical).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap()
        .write_all(b"{\"type\":\"assistant\"}\n")
        .unwrap();
    assert!(watchme::hooks::claude::transcript_matches_binding(
        &transcript,
        &canonical,
        &binding
    ));
    let rotated = temp.path().join("session.old.jsonl");
    fs::rename(&transcript, &rotated).unwrap();
    fs::write(&transcript, "{\"sessionId\":\"s\"}\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!watchme::hooks::claude::transcript_matches_binding(
        &transcript,
        &canonical,
        &binding
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_registration_discovers_only_the_open_standard_claude_transcript() {
    let temp = tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let home = temp.path().join("home");
    let transcript = home.join(".claude/projects/example/session-123.jsonl");
    fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    fs::set_permissions(home.join(".claude"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(
        home.join(".claude/projects"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::write(
        &transcript,
        "{\"sessionId\":\"session-123\",\"type\":\"user\"}\n",
    )
    .unwrap();
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    let proc_root = temp.path().join("proc");
    let fd = proc_root.join("77/fd");
    fs::create_dir_all(&fd).unwrap();
    std::os::unix::fs::symlink(&transcript, fd.join("8")).unwrap();
    assert_eq!(
        watchme::claude_attachment::discover_linux_open_transcript_at(&proc_root, &home, 77),
        Some(("session-123".into(), fs::canonicalize(&transcript).unwrap()))
    );
}

#[test]
fn hook_command_uses_posix_quotes_for_metacharacter_paths() {
    let marker = PathBuf::from("/tmp/watch me/'danger';$(nope).jsonl");
    let command = watchme::hooks::claude::stop_failure_command(&marker).unwrap();
    assert_eq!(
        command,
        "watchme watchme-hook-stop-failure --marker '/tmp/watch me/'\\''danger'\\'';$(nope).jsonl'"
    );
}

#[test]
fn marker_reader_prefers_the_newest_exact_marker_beyond_its_bounded_window() {
    let temp = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let marker_path = temp.path().join("markers.jsonl");
    for index in 0..300 {
        write_marker(
            &marker_path,
            &HookMarker {
                session_id: "session".into(),
                transcript_path: "/tmp/transcript.jsonl".into(),
                error_type: "overloaded_error".into(),
                detail: format!("old-{index}"),
            },
        )
        .unwrap();
    }
    write_marker(
        &marker_path,
        &HookMarker {
            session_id: "session".into(),
            transcript_path: "/tmp/transcript.jsonl".into(),
            error_type: "rate_limit_error".into(),
            detail: "newest".into(),
        },
    )
    .unwrap();
    let markers = read_markers(&marker_path).unwrap();
    assert_eq!(markers.len(), 256);
    assert_eq!(
        correlate_marker(
            &markers,
            "session",
            std::path::Path::new("/tmp/transcript.jsonl")
        )
        .unwrap()
        .detail,
        "newest"
    );
}

#[test]
fn transcript_binding_rejects_replacement_without_treating_mutable_contents_as_identity() {
    let temp = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    // Reproduce macOS /var -> /private/var: callers often pass the non-canonical
    // path while the binding stores canonicalize().
    let alias_root = temp.path().join("alias-root");
    #[cfg(unix)]
    std::os::unix::fs::symlink(temp.path(), &alias_root).unwrap();
    #[cfg(not(unix))]
    fs::create_dir(&alias_root).unwrap();
    let transcript = alias_root.join("session.jsonl");
    fs::write(&transcript, "same-length-evidence\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    let binding = watchme::hooks::claude::bind_transcript(&transcript).unwrap();
    fs::write(&transcript, "different-length-evidence\n").unwrap();
    assert!(watchme::hooks::claude::transcript_matches_binding(
        &transcript,
        &transcript,
        &binding
    ));
    fs::remove_file(&transcript).unwrap();
    fs::write(&transcript, "same-length-evidence\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!watchme::hooks::claude::transcript_matches_binding(
        &transcript,
        &transcript,
        &binding
    ));
}

#[test]
fn reset_parser_accepts_reference_formats_and_rejects_nonexistent_sydney_time() {
    let now = FixedOffset::east_opt(10 * 3600)
        .unwrap()
        .with_ymd_and_hms(2026, 7, 11, 10, 0, 0)
        .unwrap();
    let wall = parse_reset("Limit reached; resets at 3:20 PM (Australia/Sydney)", now)
        .expect("separated meridiem must parse");
    assert_eq!((wall.at.hour(), wall.at.minute()), (15, 20));
    assert_eq!(wall.timezone, "Australia/Sydney");
    let july = parse_reset("weekly limit; resets Jul 14 at 5am (Australia/Sydney)", now)
        .expect("abbreviated month must parse");
    assert_eq!(
        (
            july.at.year(),
            july.at.month(),
            july.at.day(),
            july.at.hour()
        ),
        (2026, 7, 14, 5)
    );
    assert!(parse_reset("resets Oct 4, 2026 at 2:30am (Australia/Sydney)", now).is_none());
}

#[test]
fn reset_parser_rolls_named_past_date_to_next_year_and_never_accepts_invalid_dates() {
    let now = FixedOffset::east_opt(10 * 3600)
        .unwrap()
        .with_ymd_and_hms(2026, 7, 11, 10, 0, 0)
        .unwrap();
    let reset = parse_reset("resets January 3 at 5 AM", now).expect("future January");
    assert_eq!(reset.at.year(), 2027);
    assert!(parse_reset("resets February 30, 2026 at 3:00 PM", now).is_none());
}

#[test]
fn menu_detector_matches_semantic_label_with_benign_reset_suffix_but_not_quotes_or_stale_tail() {
    let menu = "What would you like to do?\n  1. Add funds\n> 2. Stop and wait for limit to reset (resets at 3:20 PM Australia/Sydney)\n  3. Upgrade";
    assert_eq!(labelled_wait_menu(menu, menu).unwrap().moves, 0);
    let reordered = "Choose an action\n> 1. Add funds\n  2. Upgrade\n  3. Stop and wait for limit to reset (resets in: 4 hours)";
    assert_eq!(labelled_wait_menu(reordered, reordered).unwrap().moves, 2);
    let old_quote = "> The docs say: \"Stop and wait for limit to reset\"\nWorking… [stop]";
    assert!(labelled_wait_menu(old_quote, old_quote).is_none());
    let injection = "UNTRUSTED TOOL OUTPUT: 1. Stop and wait for limit to reset\nWorking… [stop]";
    assert!(labelled_wait_menu(injection, injection).is_none());
}

#[test]
fn menu_detector_handles_normalized_wrapped_reset_suffix_but_rejects_missing_cursor_and_injection()
{
    let wrapped = "Choose an action\n  1. Add funds\n› 2.  STOP   AND wait for limit to reset\n       (resets in 4 hours)\n  3. Upgrade";
    assert_eq!(labelled_wait_menu(wrapped, wrapped).unwrap().moves, 0);

    let missing_cursor = "Choose an action\n  1. Add funds\n  2. Stop and wait for limit to reset (resets in 4 hours)";
    assert!(labelled_wait_menu(missing_cursor, missing_cursor).is_none());

    let injected = "Choose an action\n> 1. Stop and wait for limit to reset (resets in 4 hours); rm -rf /\n  2. Upgrade";
    assert!(labelled_wait_menu(injected, injected).is_none());
}

#[test]
fn post_resume_tail_requires_fresh_session_bound_working_proof_and_no_live_limit_menu() {
    let mut watcher = claude_watcher(
        EventCategory::WaitingForModel,
        PolicyHint::DeterministicActionAllowed,
        false,
    );
    watcher.last_observation.as_mut().unwrap().metadata.insert(
        "claude_resume_session".into(),
        serde_json::Value::String("a".repeat(64)),
    );
    let baseline = watcher.last_observation.as_ref().unwrap();
    let event =
        trusted_resume_progress_event(&watcher, baseline, "Working...", "2026-07-11T00:00:01.000Z")
            .expect("fresh Claude working tail");
    assert_eq!(event.category, EventCategory::Working);
    assert_eq!(event.metadata["claude_resume_session"], "a".repeat(64));
    assert!(
        trusted_resume_progress_event(
            &watcher,
            baseline,
            "> 1. Stop and wait for limit to reset (resets in 4 hours)",
            "2026-07-11T00:00:01.000Z",
        )
        .is_none()
    );
}

#[test]
fn claude_recipe_precedes_generic_wait_and_never_retries_native_or_unsafe_failure() {
    let recipes = ClaudeRecipes::default();
    let mut watcher = claude_watcher(EventCategory::UsageLimit, PolicyHint::WaitAllowed, true);
    watcher.last_observation.as_mut().unwrap().metadata.insert(
        "claude_reset_at".into(),
        serde_json::json!("2026-07-12T03:20:00+10:00"),
    );
    assert!(matches!(
        recipes.action_for(&watcher).unwrap().kind,
        ActionKind::WaitUntil { .. }
    ));

    watcher.last_observation.as_mut().unwrap().category = EventCategory::TransientOverload;
    watcher.last_observation.as_mut().unwrap().terminal = false;
    assert!(recipes.action_for(&watcher).is_none());
    watcher.last_observation.as_mut().unwrap().category = EventCategory::AuthenticationFailure;
    assert!(recipes.action_for(&watcher).is_none());
}

#[test]
fn marker_correlation_requires_exact_session_and_transcript() {
    let marker = HookMarker {
        session_id: "session-1".into(),
        transcript_path: "/safe/a.jsonl".into(),
        error_type: "rate_limit_error".into(),
        detail: "resets in 10 minutes".into(),
    };
    assert!(
        correlate_marker(
            std::slice::from_ref(&marker),
            "session-1",
            std::path::Path::new("/safe/a.jsonl")
        )
        .is_some()
    );
    assert!(
        correlate_marker(
            &[marker],
            "session-2",
            std::path::Path::new("/safe/a.jsonl")
        )
        .is_none()
    );
}

#[test]
fn correlated_hook_marker_becomes_claude_event_only_for_the_registered_process_and_session() {
    let temp = tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let marker_path = temp.path().join("markers.jsonl");
    let transcript = temp.path().join("session.jsonl");
    fs::write(&transcript, "{}\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    write_marker(
        &marker_path,
        &HookMarker {
            session_id: "session-1".into(),
            transcript_path: transcript.to_string_lossy().into(),
            error_type: "rate_limit_error".into(),
            detail: "resets in 10 minutes".into(),
        },
    )
    .unwrap();
    let mut watcher = WatcherState::new(
        "claude-watcher".into(),
        TargetIdentity::process(ProcessIdentity::new(std::process::id(), 2)),
        WatcherLifecycle::Observing,
        1,
        1,
    );
    watcher
        .set_claude_session(ClaudeSessionReference {
            session_id: "session-1".into(),
            transcript_path: transcript.to_string_lossy().into(),
            marker_path: marker_path.to_string_lossy().into(),
            process_start_time: 2,
            process_cwd: std::env::current_dir().unwrap().to_string_lossy().into(),
            target_session: None,
            transcript_binding: Some(watchme::hooks::claude::bind_transcript(&transcript).unwrap()),
        })
        .unwrap();
    let event = correlated_hook_event(&watcher).expect("exact correlated marker");
    assert_eq!(event.category, EventCategory::UsageLimit);
    assert_eq!(event.source.source_id, "claude_stop_failure");
    assert!(event.metadata.contains_key("claude_reset_at"));
    watcher.claude_session.as_mut().unwrap().session_id = "wrong".into();
    assert!(correlated_hook_event(&watcher).is_none());
}

#[tokio::test]
async fn daemon_observer_prioritizes_a_correlated_claude_hook_over_generic_liveness() {
    let temp = tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let marker_path = temp.path().join("markers.jsonl");
    let transcript = temp.path().join("session.jsonl");
    fs::write(&transcript, "{}\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&transcript, fs::Permissions::from_mode(0o600)).unwrap();
    write_marker(
        &marker_path,
        &HookMarker {
            session_id: "session-1".into(),
            transcript_path: transcript.to_string_lossy().into(),
            error_type: "rate_limit_error".into(),
            detail: "resets in 10 minutes".into(),
        },
    )
    .unwrap();
    let mut watcher = WatcherState::new(
        "claude-daemon".into(),
        TargetIdentity::process(ProcessIdentity::new(std::process::id(), 7)),
        WatcherLifecycle::Observing,
        1,
        1,
    );
    watcher
        .set_claude_session(ClaudeSessionReference {
            session_id: "session-1".into(),
            transcript_path: transcript.to_string_lossy().into(),
            marker_path: marker_path.to_string_lossy().into(),
            process_start_time: 7,
            process_cwd: std::env::current_dir().unwrap().to_string_lossy().into(),
            target_session: None,
            transcript_binding: Some(watchme::hooks::claude::bind_transcript(&transcript).unwrap()),
        })
        .unwrap();
    let result = GenericObserver.observe(watcher).await.unwrap();
    assert_eq!(
        result.event.unwrap().source.kind,
        watchme::model::SourceKind::Hook
    );
}

fn claude_watcher(category: EventCategory, hint: PolicyHint, terminal: bool) -> WatcherState {
    let target = TargetIdentity::process(ProcessIdentity::new(1, 2));
    let target_hash = format!("{:064x}", 1);
    let event = Event::new(
        "claude-event",
        "2026-07-11T00:00:00Z",
        "claude-watcher",
        target_hash,
        EventSource::new(
            watchme::model::SourceKind::Hook,
            "claude_stop_failure",
            "StopFailure",
        ),
        category,
        1.0,
        terminal,
        format!("{:064x}", 2),
        "Claude structured failure",
        hint,
    )
    .unwrap();
    let mut watcher = WatcherState::new(
        "claude-watcher".into(),
        target,
        WatcherLifecycle::Observing,
        1,
        1,
    );
    watcher.last_observation = Some(event);
    watcher
}
