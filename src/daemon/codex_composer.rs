use crate::mux::ComposerState;

/// Interpret only the current Codex composer/footer region. Herdr's recent
/// capture also includes ordinary output and status lines, so the final line
/// alone is not composer evidence. Unknown layouts fail closed.
pub(super) fn state_from_recent(text: &str) -> ComposerState {
    const EMPTY_PLACEHOLDERS: &[&str] = &[
        "Explain this codebase",
        "Summarize recent commits",
        "Implement {feature}",
        "Find and fix a bug in @filename",
        "Write tests for @filename",
        "Improve documentation in @filename",
        "Run /review on my current changes",
        "Use /skills to list available skills",
        "Check recently modified functions for compatibility",
        "How many files have been modified?",
        "Will this algorithm scale well?",
    ];

    let lines = text.lines().collect::<Vec<_>>();
    let Some(prompt_index) = lines
        .iter()
        .rposition(|line| line.trim_start().starts_with('›'))
    else {
        return ComposerState::Unknown;
    };
    let prompt = lines[prompt_index]
        .trim_start()
        .strip_prefix('›')
        .expect("prompt marker was checked")
        .trim();
    let after = &lines[prompt_index + 1..];
    let Some(footer_index) = after.iter().rposition(|line| !line.trim().is_empty()) else {
        return ComposerState::Unknown;
    };
    let footer = after[footer_index].trim();
    let has_only_spacing_before_footer = after[..footer_index]
        .iter()
        .all(|line| line.trim().is_empty());
    let looks_like_codex_footer = footer.matches(" · ").count() >= 2
        && (footer.contains("Context ")
            || footer.contains("Goal blocked")
            || footer.contains("Pursuing goal"));

    if !has_only_spacing_before_footer || !looks_like_codex_footer {
        return ComposerState::Unsafe;
    }
    if prompt.is_empty() || EMPTY_PLACEHOLDERS.contains(&prompt) {
        ComposerState::Safe
    } else {
        ComposerState::Unsafe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_known_empty_placeholder_before_footer() {
        let screen = concat!(
            "• Goal blocked\n",
            "\n",
            "› Implement {feature}\n",
            "\n",
            "  gpt-5.6-sol high · ~/src/demo · Context 29% used · Goal blocked\n",
        );

        assert_eq!(state_from_recent(screen), ComposerState::Safe);
    }

    #[test]
    fn rejects_typed_or_multiline_input() {
        for screen in [
            "› keep my draft\n\n  gpt-5.6-sol · Context 29% used · Goal blocked\n",
            "› Implement {feature}\nsecond typed line\n\n  gpt-5.6-sol · Context 29% used\n",
        ] {
            assert_eq!(state_from_recent(screen), ComposerState::Unsafe);
        }
    }

    #[test]
    fn fails_closed_without_a_current_prompt_and_footer() {
        for screen in ["• ordinary output\n", "› Implement {feature}\n"] {
            assert_eq!(state_from_recent(screen), ComposerState::Unknown);
        }
        assert_eq!(
            state_from_recent(
                "› A future unknown placeholder\n\n  gpt-5.6-sol · Context 29% used\n"
            ),
            ComposerState::Unsafe
        );
    }
}
