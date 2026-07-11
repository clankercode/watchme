//! Conservative redaction for snapshots, logs, and planner inputs.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RedactionReport {
    pub replacement_count: usize,
    pub categories: BTreeSet<String>,
}

impl RedactionReport {
    fn mark(&mut self, category: &str, count: usize) {
        if count == 0 {
            return;
        }
        self.replacement_count += count;
        self.categories.insert(category.to_owned());
    }

    pub fn merge(&mut self, other: &RedactionReport) {
        self.replacement_count += other.replacement_count;
        self.categories.extend(other.categories.iter().cloned());
    }
}

type Pattern = (&'static str, Regex, &'static str);

fn patterns() -> &'static [Pattern] {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            vec![
                (
                    "private_key",
                    Regex::new(
                        r"(?is)-----BEGIN [^\-\r\n]*PRIVATE KEY-----.*?-----END [^\-\r\n]*PRIVATE KEY-----",
                    )
                    .expect("private key pattern"),
                    "<REDACTED:PRIVATE_KEY>",
                ),
                (
                    "authorization_header",
                    Regex::new(r"(?im)^(Authorization\s*:\s*(?:Bearer|Basic)\s+)[^\s]+")
                        .expect("auth header pattern"),
                    "${1}<REDACTED:AUTH>",
                ),
                (
                    "jwt",
                    Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
                        .expect("jwt pattern"),
                    "<REDACTED:JWT>",
                ),
                (
                    "known_token",
                    Regex::new(
                        r"\b(?:sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{16,}|AKIA[0-9A-Z]{16})\b",
                    )
                    .expect("token pattern"),
                    "<REDACTED:TOKEN>",
                ),
                (
                    "secret_assignment",
                    Regex::new(
                        r#"(?i)\b((?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|cookie|session[_-]?token)\s*[:=]\s*)(?:['"])?([^\s,'";]{6,})(?:['"])?"#,
                    )
                    .expect("secret assignment pattern"),
                    "${1}<REDACTED:SECRET>",
                ),
                (
                    "database_url",
                    Regex::new(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+(@[^\s]+)")
                        .expect("database url pattern"),
                    "${1}<REDACTED:PASSWORD>${2}",
                ),
            ]
        })
        .as_slice()
}

fn sensitive_query_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "access_token"
            | "api_key"
            | "apikey"
            | "auth"
            | "authorization"
            | "credential"
            | "key"
            | "password"
            | "secret"
            | "signature"
            | "sig"
            | "token"
            | "x-amz-credential"
            | "x-amz-signature"
            | "x-goog-signature"
    ) || lower.ends_with("token")
        || lower.ends_with("signature")
}

fn redact_urls(text: &str, report: &mut RedactionReport) -> String {
    static URL_RE: OnceLock<Regex> = OnceLock::new();
    let url_re = URL_RE.get_or_init(|| Regex::new(r#"https?://[^\s<>"']+"#).expect("url pattern"));
    url_re
        .replace_all(text, |caps: &regex::Captures| {
            let mut value = caps[0].to_owned();
            let mut trailing = String::new();
            while value
                .chars()
                .last()
                .is_some_and(|c| matches!(c, '.' | ',' | ')' | ';' | ']'))
            {
                if let Some(ch) = value.pop() {
                    trailing.insert(0, ch);
                }
            }
            let Some((base, query)) = value.split_once('?') else {
                return caps[0].to_owned();
            };
            let (query, fragment) = match query.split_once('#') {
                Some((q, f)) => (q, Some(f)),
                None => (query, None),
            };
            let mut changed = false;
            let mut pairs = Vec::new();
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (key, val) = pair.split_once('=').unwrap_or((pair, ""));
                if sensitive_query_key(key) {
                    pairs.push(format!("{key}=<REDACTED>"));
                    changed = true;
                } else {
                    pairs.push(format!("{key}={val}"));
                }
            }
            if !changed {
                return caps[0].to_owned();
            }
            report.mark("signed_url", 1);
            let mut rebuilt = format!("{base}?{}", pairs.join("&"));
            if let Some(fragment) = fragment {
                rebuilt.push('#');
                rebuilt.push_str(fragment);
            }
            rebuilt.push_str(&trailing);
            rebuilt
        })
        .into_owned()
}

fn apply_pattern(text: &str, pattern: &Regex, replacement: &str) -> (String, usize) {
    let count = pattern.find_iter(text).count();
    if count == 0 {
        return (text.to_owned(), 0);
    }
    (pattern.replace_all(text, replacement).into_owned(), count)
}

/// Redact secrets, tokens, cookies, and signed-URL query parameters from text.
pub fn redact_text(text: &str, extra_secret_names: &[String]) -> (String, RedactionReport) {
    let mut report = RedactionReport::default();
    let mut output = text.to_owned();
    for (category, pattern, replacement) in patterns() {
        let (next, count) = apply_pattern(&output, pattern, replacement);
        output = next;
        report.mark(category, count);
    }

    if !extra_secret_names.is_empty() {
        let safe: Vec<String> = extra_secret_names
            .iter()
            .filter(|name| !name.is_empty())
            .map(|name| regex::escape(name))
            .collect();
        if !safe.is_empty() {
            let pattern = Regex::new(&format!(
                r#"(?im)^((?:{})\s*[:=]\s*)(?:['"])?([^\s'"]+)(?:['"])?$"#,
                safe.join("|")
            ))
            .expect("custom secret pattern");
            let (next, count) = apply_pattern(&output, &pattern, "${1}<REDACTED:CUSTOM_SECRET>");
            output = next;
            report.mark("custom_secret", count);
        }
    }

    output = redact_urls(&output, &mut report);
    (output, report)
}

fn sensitive_field_name(key: &str, extra_secret_names: &[String]) -> bool {
    let lower = key.to_ascii_lowercase();
    sensitive_query_key(&lower)
        || lower.contains("password")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("cookie")
        || extra_secret_names.iter().any(|name| name == key)
}

/// Recursively redact JSON string leaves and sensitive object fields.
pub fn redact_json(value: &Value, extra_secret_names: &[String]) -> (Value, RedactionReport) {
    let mut report = RedactionReport::default();
    let redacted = walk(value, extra_secret_names, &mut report);
    (redacted, report)
}

fn walk(value: &Value, extra_secret_names: &[String], report: &mut RedactionReport) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, child) in map {
                if sensitive_field_name(key, extra_secret_names) {
                    out.insert(key.clone(), Value::String("<REDACTED:FIELD>".into()));
                    report.mark("sensitive_field", 1);
                } else {
                    out.insert(key.clone(), walk(child, extra_secret_names, report));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| walk(item, extra_secret_names, report))
                .collect(),
        ),
        Value::String(text) => {
            let (redacted, partial) = redact_text(text, extra_secret_names);
            report.merge(&partial);
            Value::String(redacted)
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_redacts_authorization_and_keeps_uuid() {
        let (redacted, report) = redact_text(
            "Authorization: Bearer sk-test_abcdefghijklmnopqrstuvwxyz012345",
            &[],
        );
        assert!(!redacted.contains("abcdefghijklmnopqrstuvwxyz012345"));
        assert!(report.replacement_count >= 1);
        let (normal, empty) =
            redact_text("const id = '123e4567-e89b-12d3-a456-426614174000';", &[]);
        assert_eq!(normal, "const id = '123e4567-e89b-12d3-a456-426614174000';");
        assert_eq!(empty.replacement_count, 0);
    }
}
