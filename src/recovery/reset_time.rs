//! Conservative parser for human-facing Claude reset messages.
//!
//! It deliberately accepts only messages with a reset/retry cue.  IANA zones
//! use chrono-tz's local-time resolver: nonexistent DST wall times are refused
//! and an ambiguous fall-back time is deterministically resolved to its earliest
//! future instant.
use chrono::{
    DateTime, Datelike, Duration, FixedOffset, LocalResult, NaiveDate, NaiveTime, TimeZone,
};
use chrono_tz::Tz;

const MIN_WALL_FUTURE_SECONDS: i64 = 300;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResetTime {
    pub at: DateTime<FixedOffset>,
    pub confidence_milli: u16,
    pub timezone: String,
    pub margin_seconds: u64,
}

#[derive(Clone, Copy)]
enum Zone {
    Iana(Tz),
    Fixed(FixedOffset),
}

impl Zone {
    fn from_text(text: &str, fallback: FixedOffset) -> Self {
        text.split_whitespace()
            .map(|token| {
                token.trim_matches(|value: char| !value.is_ascii_alphanumeric() && value != '/')
            })
            .find_map(|token| {
                token
                    .contains('/')
                    .then(|| token.parse::<Tz>().ok())
                    .flatten()
            })
            .map_or(Self::Fixed(fallback), Self::Iana)
    }

    fn name(self) -> String {
        match self {
            Self::Iana(zone) => zone.name().to_owned(),
            Self::Fixed(offset) => offset.to_string(),
        }
    }

    fn local_date(self, now: DateTime<FixedOffset>) -> NaiveDate {
        match self {
            Self::Iana(zone) => now.with_timezone(&zone).date_naive(),
            Self::Fixed(_) => now.date_naive(),
        }
    }

    fn resolve(
        self,
        date: NaiveDate,
        hour: u32,
        minute: u32,
        now: DateTime<FixedOffset>,
    ) -> Option<DateTime<FixedOffset>> {
        let local = date.and_time(NaiveTime::from_hms_opt(hour, minute, 0)?);
        let candidates = match self {
            Self::Iana(zone) => match zone.from_local_datetime(&local) {
                LocalResult::None => return None,
                LocalResult::Single(value) => vec![value.fixed_offset()],
                // The earliest future instant is the documented policy.  This
                // keeps a repeated fall-back clock time deterministic.
                LocalResult::Ambiguous(first, second) => {
                    vec![first.fixed_offset(), second.fixed_offset()]
                }
            },
            Self::Fixed(offset) => vec![offset.from_local_datetime(&local).single()?],
        };
        candidates
            .into_iter()
            .filter(|candidate| candidate.timestamp() > now.timestamp())
            .min_by_key(DateTime::timestamp)
    }
}

/// Parse a reset into an absolute instant.  Dates without an explicit year may
/// roll into the next year; explicit past dates are rejected instead of guessed.
pub fn parse_reset(text: &str, now: DateTime<FixedOffset>) -> Option<ResetTime> {
    if text.is_empty() || text.len() > 500 {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    if !(lower.contains("reset") || lower.contains("try again")) {
        return None;
    }
    if let Some(duration) = parse_relative(&lower) {
        return Some(ResetTime {
            at: now + duration,
            confidence_milli: 980,
            timezone: now.offset().to_string(),
            margin_seconds: 60,
        });
    }
    let zone = Zone::from_text(text, *now.offset());
    let (hour, minute) = parse_clock(&lower)?;
    let (date, named_date, explicit_year) = parse_date(&lower, zone.local_date(now))?;
    let mut candidate = zone.resolve(date, hour, minute, now);
    if candidate.is_none() && named_date && !explicit_year {
        candidate = zone.resolve(
            date.with_year(date.year().checked_add(1)?)?,
            hour,
            minute,
            now,
        );
    }
    if candidate.is_none() && !named_date {
        for days in 1..=2 {
            if let Some(next) = zone.resolve(date + Duration::days(days), hour, minute, now) {
                candidate = Some(next);
                break;
            }
        }
    }
    let at = candidate?;
    if !named_date && at.timestamp().saturating_sub(now.timestamp()) < MIN_WALL_FUTURE_SECONDS {
        return None;
    }
    Some(ResetTime {
        at,
        confidence_milli: if named_date { 930 } else { 860 },
        timezone: zone.name(),
        margin_seconds: 60,
    })
}

fn parse_relative(text: &str) -> Option<Duration> {
    let start = text
        .find("resets in")
        .or_else(|| text.find("reset in"))
        .or_else(|| text.find("try again in"))?;
    let fragment = &text[start..];
    let mut number = None;
    let mut seconds = 0_i64;
    for token in words(fragment) {
        if let Ok(value) = token.parse::<i64>() {
            number = Some(value);
            continue;
        }
        let Some(value) = number.take() else { continue };
        let multiplier = if token.starts_with('h') {
            3600
        } else if token.starts_with('m') {
            60
        } else if token.starts_with('s') {
            1
        } else {
            return None;
        };
        seconds = seconds.checked_add(value.checked_mul(multiplier)?)?;
        if seconds > 31_536_000 {
            return None;
        }
    }
    (seconds > 0).then(|| Duration::seconds(seconds))
}

fn parse_clock(text: &str) -> Option<(u32, u32)> {
    let tokens = words(text);
    for (index, token) in tokens.iter().enumerate() {
        let (digits, suffix) = split_meridiem(token);
        let following_meridiem = tokens.get(index + 1).and_then(meridiem);
        let (hour, minute) = if let Some((hour, minute)) = digits.split_once(':') {
            (hour.parse::<u32>().ok()?, minute.parse::<u32>().ok()?)
        } else if suffix.is_some() || following_meridiem.is_some() {
            (digits.parse::<u32>().ok()?, 0)
        } else {
            continue;
        };
        let meridiem = suffix.or(following_meridiem);
        let hour = match meridiem {
            Some(is_pm) if (1..=12).contains(&hour) => hour % 12 + u32::from(is_pm) * 12,
            Some(_) => continue,
            None if hour <= 23 => hour,
            None => continue,
        };
        if minute < 60 {
            return Some((hour, minute));
        }
    }
    None
}

fn parse_date(text: &str, fallback: NaiveDate) -> Option<(NaiveDate, bool, bool)> {
    let tokens = words(text);
    for (index, token) in tokens.iter().enumerate() {
        let Some(month) = month(token) else { continue };
        let day = tokens.get(index + 1)?.parse::<u32>().ok()?;
        let explicit_year = tokens.get(index + 2).and_then(|value| {
            (value.len() == 4)
                .then(|| value.parse::<i32>().ok())
                .flatten()
        });
        let date = NaiveDate::from_ymd_opt(explicit_year.unwrap_or(fallback.year()), month, day)?;
        return Some((date, true, explicit_year.is_some()));
    }
    Some((fallback, false, false))
}

fn words(text: &str) -> Vec<&str> {
    text.split(|value: char| !value.is_ascii_alphanumeric() && value != ':')
        .filter(|value| !value.is_empty())
        .collect()
}

fn split_meridiem(token: &str) -> (&str, Option<bool>) {
    if let Some(value) = token.strip_suffix("am") {
        (value, Some(false))
    } else if let Some(value) = token.strip_suffix("pm") {
        (value, Some(true))
    } else {
        (token, None)
    }
}

fn meridiem(token: &&str) -> Option<bool> {
    match *token {
        "am" => Some(false),
        "pm" => Some(true),
        _ => None,
    }
}

fn month(token: &str) -> Option<u32> {
    match &token[..token.len().min(3)] {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}
