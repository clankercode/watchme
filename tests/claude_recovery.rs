use std::fs;

use chrono::{FixedOffset, TimeZone};
use tempfile::tempdir;
use watchme::agents::claude::{
    ClaudeClass, DEFAULT_RESUME, classify_screen, classify_stop_failure, labelled_wait_menu,
    menu_keys,
};
use watchme::hooks::claude::{
    HookMarker, install_stop_failure_hook, read_markers, remove_stop_failure_hook,
};
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
fn live_screen_menu_uses_label_never_option_number_and_requires_stability() {
    let screen =
        "Choose an action\n  1. Add funds\n> 2. Stop and wait for limit to reset\n  3. Upgrade";
    let menu = labelled_wait_menu(screen, screen).expect("stable menu");
    assert_eq!(menu.moves, 0);
    assert_eq!(menu_keys(&menu), ["ENTER"]);
    assert_eq!(DEFAULT_RESUME, "Continue exactly where you left off.");
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
    let marker = temp.path().join("markers.jsonl");
    assert!(install_stop_failure_hook(&settings, &marker).unwrap());
    assert!(!install_stop_failure_hook(&settings, &marker).unwrap());
    assert!(
        fs::read_to_string(&settings)
            .unwrap()
            .contains("PreToolUse")
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
