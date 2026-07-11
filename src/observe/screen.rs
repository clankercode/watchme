#[derive(Default)]
pub struct TerminalSanitizer {
    state: EscapeState,
    utf8_remaining: u8,
}
#[derive(Default)]
enum EscapeState {
    #[default]
    Text,
    Esc,
    Csi,
    String,
    StringEnd,
}
impl TerminalSanitizer {
    pub fn feed(&mut self, input: &[u8], max_bytes: usize, max_lines: usize) -> String {
        let mut out = Vec::with_capacity(input.len().min(max_bytes));
        let mut lines = 1;
        for &byte in input {
            if matches!(self.state, EscapeState::Text) && self.utf8_remaining > 0 {
                if (0x80..=0xbf).contains(&byte) {
                    if out.len() < max_bytes {
                        out.push(byte);
                    }
                    self.utf8_remaining -= 1;
                    continue;
                }
                // A malformed sequence cannot consume a following control byte.
                self.utf8_remaining = 0;
            }
            match self.state {
                EscapeState::Text => match byte {
                    0x1b => self.state = EscapeState::Esc,
                    0x9b => self.state = EscapeState::Csi,
                    0x90 | 0x9d | 0x98 | 0x9e | 0x9f => self.state = EscapeState::String,
                    b'\n' => {
                        if lines < max_lines && out.len() < max_bytes {
                            out.push(byte);
                            lines += 1
                        }
                    }
                    b'\r' => {}
                    0x20..=0x7e => {
                        if out.len() < max_bytes {
                            out.push(byte)
                        }
                    }
                    0xc2..=0xdf => {
                        if out.len() < max_bytes {
                            out.push(byte);
                            self.utf8_remaining = 1;
                        }
                    }
                    0xe0..=0xef => {
                        if out.len() < max_bytes {
                            out.push(byte);
                            self.utf8_remaining = 2;
                        }
                    }
                    0xf0..=0xf4 => {
                        if out.len() < max_bytes {
                            out.push(byte);
                            self.utf8_remaining = 3;
                        }
                    }
                    0xa0..=0xbf => {
                        if out.len() < max_bytes {
                            out.push(byte)
                        }
                    }
                    _ => {}
                },
                EscapeState::Esc => match byte {
                    b'[' => self.state = EscapeState::Csi,
                    b']' | b'P' | b'X' | b'^' | b'_' => self.state = EscapeState::String,
                    _ => self.state = EscapeState::Text,
                },
                EscapeState::Csi => {
                    if (0x40..=0x7e).contains(&byte) {
                        self.state = EscapeState::Text
                    }
                }
                EscapeState::String => {
                    if byte == 0x07 {
                        self.state = EscapeState::Text
                    } else if byte == 0x1b {
                        self.state = EscapeState::StringEnd
                    }
                }
                EscapeState::StringEnd => {
                    self.state = if byte == b'\\' {
                        EscapeState::Text
                    } else {
                        EscapeState::String
                    }
                }
            }
        }
        let text = String::from_utf8_lossy(&out);
        let mut sanitized: String = text
            .chars()
            .filter(|c| !matches!(*c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'))
            .collect();
        if sanitized.len() > max_bytes {
            let mut boundary = max_bytes;
            while boundary > 0 && !sanitized.is_char_boundary(boundary) {
                boundary -= 1;
            }
            sanitized.truncate(boundary);
        }
        sanitized
    }
}

/// Returns only the bounded live bottom, excluding common quote/history chrome.
pub fn live_bottom(input: &[u8], max_bytes: usize, max_lines: usize) -> String {
    let sanitized = sanitize_terminal(input, max_bytes, max_lines.saturating_mul(4));
    let mut lines: Vec<&str> = sanitized
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with('>')
                && !trimmed.starts_with("│")
                && !trimmed.starts_with("history:")
        })
        .collect();
    if lines.len() > max_lines {
        lines.drain(..lines.len() - max_lines);
    }
    lines.join("\n")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineProvenance {
    LiveOutput,
    Transcript,
    CodeFence,
    Pasted,
    Quote,
    Chrome,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScreenLine {
    pub text: String,
    pub provenance: LineProvenance,
}
#[derive(Clone, Debug)]
pub struct LiveScreen {
    lines: Vec<ScreenLine>,
    trusted_boundary: Option<usize>,
    touches_bottom: bool,
}
impl LiveScreen {
    pub fn from_adapter(
        lines: Vec<ScreenLine>,
        trusted_boundary: Option<usize>,
        touches_bottom: bool,
    ) -> Self {
        Self {
            lines,
            trusted_boundary,
            touches_bottom,
        }
    }
    pub fn actionable_bottom(&self, max_lines: usize) -> Option<String> {
        let boundary = self.trusted_boundary?;
        if !self.touches_bottom || boundary >= self.lines.len() {
            return None;
        }
        let eligible: Vec<_> = self.lines[boundary..]
            .iter()
            .filter(|line| line.provenance == LineProvenance::LiveOutput)
            .collect();
        if eligible.is_empty() || self.lines.last()?.provenance != LineProvenance::LiveOutput {
            return None;
        }
        Some(
            eligible
                .into_iter()
                .rev()
                .take(max_lines)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .map(|line| line.text.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }
}
pub fn sanitize_terminal(input: &[u8], max_bytes: usize, max_lines: usize) -> String {
    TerminalSanitizer::default().feed(input, max_bytes, max_lines)
}
pub struct ScreenDebouncer {
    required: u8,
    last: Option<String>,
    stable: u8,
}
impl ScreenDebouncer {
    pub fn new(required: u8) -> Self {
        Self {
            required: required.max(2),
            last: None,
            stable: 0,
        }
    }
    pub fn observe(&mut self, fingerprint: &str, terminal_failure: bool) -> bool {
        if terminal_failure {
            return true;
        }
        if self.last.as_deref() == Some(fingerprint) {
            self.stable = self.stable.saturating_add(1)
        } else {
            self.last = Some(fingerprint.into());
            self.stable = 1
        }
        self.stable >= self.required
    }
}
