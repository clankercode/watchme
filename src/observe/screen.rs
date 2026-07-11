#[derive(Default)]
pub struct TerminalSanitizer {
    state: EscapeState,
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
            match self.state {
                EscapeState::Text => match byte {
                    0x1b => self.state = EscapeState::Esc,
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
                    0x80..=0xff => {
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
