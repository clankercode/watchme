//! Strict reset-time parser. Absence of an explicit reset cue is never inferred.
use chrono::{DateTime, Datelike, Duration, FixedOffset, NaiveDate, NaiveTime, TimeZone};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResetTime {
    pub at: DateTime<FixedOffset>,
    pub confidence_milli: u16,
    pub timezone: String,
    pub margin_seconds: u64,
}

pub fn parse_reset(text: &str, now: DateTime<FixedOffset>) -> Option<ResetTime> {
    let lower = text.to_ascii_lowercase();
    let cue = lower.contains("reset") || lower.contains("resets");
    if !cue || text.len() > 500 {
        return None;
    }
    if let Some((hours, minutes)) = relative(&lower) {
        return Some(ResetTime {
            at: now + Duration::hours(hours) + Duration::minutes(minutes),
            confidence_milli: 1000,
            timezone: now.offset().to_string(),
            margin_seconds: 60,
        });
    }
    let zone: &dyn Zone = if lower.contains("australia/sydney") {
        &Sydney
    } else {
        &Fixed(*now.offset())
    };
    let (hour, minute, pm) = clock(&lower)?;
    let mut date = date_from(&lower, now)?;
    let mut hour = hour;
    if let Some(is_pm) = pm {
        hour = match (hour, is_pm) {
            (12, false) => 0,
            (12, true) => 12,
            (h, true) => h + 12,
            (h, false) => h,
        };
    }
    if hour > 23 || minute > 59 {
        return None;
    }
    let offset = zone.offset(date);
    let at = offset
        .from_local_datetime(&date.and_time(NaiveTime::from_hms_opt(hour, minute, 0)?))
        .single()?;
    if at <= now {
        date = if has_named_date(&lower) {
            date.with_year(date.year().checked_add(1)?)?
        } else {
            date.succ_opt()?
        };
        let offset = zone.offset(date);
        return Some(ResetTime {
            at: offset
                .from_local_datetime(&date.and_time(NaiveTime::from_hms_opt(hour, minute, 0)?))
                .single()?,
            confidence_milli: 800,
            timezone: zone.name().into(),
            margin_seconds: 60,
        });
    }
    Some(ResetTime {
        at,
        confidence_milli: 900,
        timezone: zone.name().into(),
        margin_seconds: 60,
    })
}

fn has_named_date(text: &str) -> bool {
    [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ]
    .iter()
    .any(|month| text.contains(month))
}

fn relative(text: &str) -> Option<(i64, i64)> {
    let after = text
        .split("in:")
        .nth(1)
        .or_else(|| text.split("in ").nth(1))?;
    let nums: Vec<i64> = after
        .split_whitespace()
        .filter_map(|part| part.parse().ok())
        .collect();
    let hours = if after.contains("hour") {
        *nums.first()?
    } else {
        0
    };
    let minutes = if after.contains("minute") {
        *nums.get(usize::from(after.contains("hour")))?
    } else {
        0
    };
    (hours > 0 || minutes > 0).then_some((hours, minutes))
}
fn clock(text: &str) -> Option<(u32, u32, Option<bool>)> {
    let token = text
        .split_whitespace()
        .find(|part| part.contains(':'))
        .or_else(|| {
            text.split_whitespace()
                .find(|part| part.ends_with("am") || part.ends_with("pm"))
        })?;
    let clean = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != ':');
    let (digits, meridiem) = if let Some(value) = clean.strip_suffix("am") {
        (value, Some(false))
    } else if let Some(value) = clean.strip_suffix("pm") {
        (value, Some(true))
    } else {
        (clean, None)
    };
    let (h, m) = match digits.split_once(':') {
        Some((h, m)) => (h.parse().ok()?, m.parse().ok()?),
        None => (digits.parse().ok()?, 0),
    };
    Some((h, m, meridiem))
}
fn date_from(text: &str, now: DateTime<FixedOffset>) -> Option<NaiveDate> {
    let months = [
        ("jan", 1),
        ("feb", 2),
        ("mar", 3),
        ("apr", 4),
        ("may", 5),
        ("jun", 6),
        ("jul", 7),
        ("aug", 8),
        ("sep", 9),
        ("oct", 10),
        ("nov", 11),
        ("dec", 12),
    ];
    for (name, month) in months {
        if let Some(rest) = text.split(name).nth(1) {
            let day: u32 = rest
                .split_whitespace()
                .next()?
                .trim_matches(|c: char| !c.is_ascii_digit())
                .parse()
                .ok()?;
            let year = rest
                .split_whitespace()
                .find_map(|x| (x.len() == 4).then(|| x.parse().ok()).flatten())
                .unwrap_or(now.year());
            return NaiveDate::from_ymd_opt(year, month, day);
        }
    }
    NaiveDate::from_ymd_opt(now.year(), now.month(), now.day())
}
trait Zone {
    fn offset(&self, date: NaiveDate) -> FixedOffset;
    fn name(&self) -> &'static str;
}
struct Fixed(FixedOffset);
impl Zone for Fixed {
    fn offset(&self, _: NaiveDate) -> FixedOffset {
        self.0
    }
    fn name(&self) -> &'static str {
        "local"
    }
}
struct Sydney;
impl Zone for Sydney {
    fn offset(&self, date: NaiveDate) -> FixedOffset {
        let y = date.year();
        let start = first_sunday(y, 10);
        let end = first_sunday(y, 4);
        let daylight = if date.month() >= 10 {
            date >= start
        } else if date.month() <= 4 {
            date < end
        } else {
            false
        };
        FixedOffset::east_opt(if daylight { 11 * 3600 } else { 10 * 3600 }).unwrap()
    }
    fn name(&self) -> &'static str {
        "Australia/Sydney"
    }
}
fn first_sunday(year: i32, month: u32) -> NaiveDate {
    let first = NaiveDate::from_ymd_opt(year, month, 1).unwrap();
    first + Duration::days(i64::from((7 - first.weekday().num_days_from_sunday()) % 7))
}
