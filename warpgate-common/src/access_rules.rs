//! Access rules: *when* a user may start a connection, and what happens outside those times.
//!
//! One set of rules is stored on an access policy (`access_policies`), whether the policy is
//! a general one (a user, an access group, a target, or a pair of them) or a direct
//! assignment's own schedule. They are only data here; the evaluator, which is the one place
//! that decides, lives in `warpgate_core::access_policy`.
//!
//! * `windows` are weekly time ranges in `timezone` (an IANA name such as `Europe/Berlin`),
//!   each with an action. A range whose end is earlier than its start runs overnight into the
//!   next day (`22:00`–`06:00`); `24:00` is the end of the day.
//! * When several windows contain the moment, the most restrictive action applies. When none
//!   does, `outside` applies. A rule set with no windows is therefore "always `outside`".
//! * `approval` says how an approval is asked for and for how long it is good, when the action
//!   is [`RuleAction::RequireApproval`].
//!
//! These rules decide whether a connection may *start*. They never end a session that is
//! already open.

use poem_openapi::{Enum, Object};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Minutes in a day: the largest value of a window's end (`24:00`).
pub const MINUTES_PER_DAY: u16 = 1440;

/// A day of the week.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Enum,
)]
#[serde(rename_all = "lowercase")]
#[oai(rename = "AccessRuleWeekday")]
pub enum RuleWeekday {
    #[oai(rename = "mon")]
    Mon,
    #[oai(rename = "tue")]
    Tue,
    #[oai(rename = "wed")]
    Wed,
    #[oai(rename = "thu")]
    Thu,
    #[oai(rename = "fri")]
    Fri,
    #[oai(rename = "sat")]
    Sat,
    #[oai(rename = "sun")]
    Sun,
}

impl RuleWeekday {
    pub const ALL: [Self; 7] = [
        Self::Mon,
        Self::Tue,
        Self::Wed,
        Self::Thu,
        Self::Fri,
        Self::Sat,
        Self::Sun,
    ];

    /// Monday is 0.
    pub const fn index(self) -> usize {
        match self {
            Self::Mon => 0,
            Self::Tue => 1,
            Self::Wed => 2,
            Self::Thu => 3,
            Self::Fri => 4,
            Self::Sat => 5,
            Self::Sun => 6,
        }
    }

    pub const fn from_index(index: usize) -> Self {
        Self::ALL[index % 7]
    }

    /// The day before this one.
    pub const fn previous(self) -> Self {
        Self::from_index(self.index() + 6)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Mon => "Mon",
            Self::Tue => "Tue",
            Self::Wed => "Wed",
            Self::Thu => "Thu",
            Self::Fri => "Fri",
            Self::Sat => "Sat",
            Self::Sun => "Sun",
        }
    }
}

/// What a moment in time means for a connection. Ordered by how restrictive it is:
/// `Allow` < `RequireApproval` < `Deny`, so the most restrictive of several is their `max`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Enum,
)]
#[serde(rename_all = "snake_case")]
#[oai(rename = "AccessRuleAction")]
pub enum RuleAction {
    /// The connection may start without anyone's approval.
    #[oai(rename = "allow")]
    Allow,
    /// The connection waits until an authorized approver grants it.
    #[oai(rename = "require_approval")]
    RequireApproval,
    /// The connection is refused, whether or not anyone would approve it.
    #[oai(rename = "deny")]
    Deny,
}

impl Default for RuleAction {
    /// Fails closed: rules read back without an action refuse rather than allow.
    fn default() -> Self {
        Self::Deny
    }
}

impl RuleAction {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::RequireApproval => "Require approval",
            Self::Deny => "Deny",
        }
    }
}

/// A weekly time range and what it means.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Object)]
#[oai(rename = "AccessRuleWindow")]
pub struct RuleWindow {
    /// The days it starts on. Empty means it never matches.
    pub days: Vec<RuleWeekday>,
    /// `HH:MM`, 24-hour, in the rules' timezone.
    pub start: String,
    /// `HH:MM`, or `24:00` for the end of the day. Earlier than `start`: the range runs
    /// overnight, into the morning of the next day.
    pub end: String,
    pub action: RuleAction,
}

/// Parse `HH:MM` into minutes since midnight; `24:00` only where `allow_end_of_day`.
pub fn parse_clock(text: &str, allow_end_of_day: bool) -> Option<u16> {
    let (hours, minutes) = text.split_once(':')?;
    let digits = |part: &str| part.len() == 2 && part.chars().all(|c| c.is_ascii_digit());
    if !digits(hours) || !digits(minutes) {
        return None;
    }
    let hours: u16 = hours.parse().ok()?;
    let minutes: u16 = minutes.parse().ok()?;
    if minutes > 59 {
        return None;
    }
    if hours == 24 && minutes == 0 && allow_end_of_day {
        return Some(MINUTES_PER_DAY);
    }
    (hours <= 23).then_some(hours * 60 + minutes)
}

/// `HH:MM` for minutes since midnight (1440 reads `24:00`).
pub fn format_clock(minutes: u16) -> String {
    format!("{:02}:{:02}", minutes / 60, minutes % 60)
}

impl RuleWindow {
    /// Start and end in minutes since midnight; `None` when either is malformed or they are
    /// equal (an empty range).
    pub fn bounds(&self) -> Option<(u16, u16)> {
        let start = parse_clock(&self.start, false)?;
        let end = parse_clock(&self.end, true)?;
        (start != end).then_some((start, end))
    }

    /// Whether the window contains `minute` (since midnight) on `day`, in the window's own
    /// timezone. An overnight window contains the evening of each listed day and the morning
    /// after it.
    pub fn contains(&self, day: RuleWeekday, minute: u16) -> bool {
        let Some((start, end)) = self.bounds() else {
            return false;
        };
        if start < end {
            self.days.contains(&day) && minute >= start && minute < end
        } else {
            (self.days.contains(&day) && minute >= start)
                || (self.days.contains(&day.previous()) && minute < end)
        }
    }
}

/// How an approval is asked for, and how long it is good, when the action is
/// [`RuleAction::RequireApproval`]. Two separate clocks: the request lapses unanswered after
/// `request_expiry_seconds`; an approval that was given can only be used to start a
/// connection for `valid_for_seconds` after it was given.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Object)]
#[oai(rename = "AccessRuleApproval")]
pub struct RuleApproval {
    /// How long a request waits for an answer. Unset: the server's approval timeout.
    #[serde(default)]
    pub request_expiry_seconds: Option<u32>,
    /// How long an approval can be used to start a connection. Unset: the same as the
    /// request's, from the moment it is given.
    #[serde(default)]
    pub valid_for_seconds: Option<u32>,
    /// Who may approve. Both empty: any administrator allowed to approve sessions.
    #[serde(default)]
    pub approver_user_ids: Vec<Uuid>,
    /// Members of these roles may approve.
    #[serde(default)]
    pub approver_role_ids: Vec<Uuid>,
}

/// The longest request expiry or approval validity an administrator may set: 30 days.
pub const MAX_APPROVAL_SECONDS: u32 = 30 * 24 * 3600;

/// When a connection may start, and what to do otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Object)]
#[oai(rename = "AccessRules")]
pub struct AccessRules {
    /// An IANA timezone name (`Europe/Berlin`, `America/New_York`, `UTC`). The windows are
    /// read in it, daylight saving included.
    pub timezone: String,
    // Required in the API (so clients always send a complete rule set); defaulted when
    // reading stored JSON, so an older or partial record still loads.
    #[serde(default)]
    pub windows: Vec<RuleWindow>,
    /// What applies when no window contains the moment.
    #[serde(default)]
    pub outside: RuleAction,
    #[serde(default)]
    pub approval: RuleApproval,
}

/// `Mon–Fri`, `Sat, Sun`, `Every day`.
pub fn describe_days(days: &[RuleWeekday]) -> String {
    let mut present = [false; 7];
    for day in days {
        present[day.index()] = true;
    }
    if present.iter().all(|&on| on) {
        return "Every day".to_owned();
    }
    let mut parts: Vec<String> = vec![];
    let mut index = 0;
    while index < 7 {
        if !present[index] {
            index += 1;
            continue;
        }
        let mut end = index;
        while end + 1 < 7 && present[end + 1] {
            end += 1;
        }
        let first = RuleWeekday::from_index(index).name();
        let last = RuleWeekday::from_index(end).name();
        match end - index {
            0 => parts.push(first.to_owned()),
            1 => {
                parts.push(first.to_owned());
                parts.push(last.to_owned());
            }
            _ => parts.push(format!("{first}–{last}")),
        }
        index = end + 1;
    }
    parts.join(", ")
}

impl AccessRules {
    /// Rules for one thing the administrator means: allow the given windows, and do
    /// `outside` the rest of the time.
    pub fn new(timezone: &str, outside: RuleAction) -> Self {
        Self {
            timezone: timezone.to_owned(),
            windows: vec![],
            outside,
            approval: RuleApproval::default(),
        }
    }

    /// A human-readable summary, as it appears in the audit log and in an approval's reason:
    /// `Mon–Fri 09:00–18:00 allow; Sat, Sun 00:00–24:00 require approval; otherwise require
    /// approval (Europe/Berlin)`.
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = self
            .windows
            .iter()
            .filter(|window| !window.days.is_empty())
            .map(|window| {
                format!(
                    "{} {}–{} {}",
                    describe_days(&window.days),
                    window.start,
                    window.end,
                    window.action.label().to_lowercase()
                )
            })
            .collect();
        parts.push(format!("otherwise {}", self.outside.label().to_lowercase()));
        format!("{} ({})", parts.join("; "), self.timezone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(days: &[RuleWeekday], start: &str, end: &str) -> RuleWindow {
        RuleWindow {
            days: days.to_vec(),
            start: start.into(),
            end: end.into(),
            action: RuleAction::Allow,
        }
    }

    #[test]
    fn clocks_parse_strictly() {
        assert_eq!(parse_clock("00:00", false), Some(0));
        assert_eq!(parse_clock("09:30", false), Some(570));
        assert_eq!(parse_clock("23:59", false), Some(1439));
        assert_eq!(parse_clock("24:00", true), Some(1440));
        assert_eq!(parse_clock("24:00", false), None);
        assert_eq!(parse_clock("24:01", true), None);
        assert_eq!(parse_clock("9:30", false), None);
        assert_eq!(parse_clock("09:60", false), None);
        assert_eq!(parse_clock("+9:30", false), None);
        assert_eq!(parse_clock("0930", false), None);
        assert_eq!(parse_clock("", false), None);
    }

    #[test]
    fn a_day_window_contains_its_range_and_nothing_else() {
        use RuleWeekday::{Fri, Mon, Sat};
        let w = window(&[Mon, Fri], "09:00", "18:00");
        assert!(w.contains(Mon, 9 * 60));
        assert!(w.contains(Fri, 17 * 60 + 59));
        assert!(!w.contains(Mon, 18 * 60), "the end is exclusive");
        assert!(!w.contains(Mon, 8 * 60 + 59));
        assert!(!w.contains(Sat, 12 * 60), "not a listed day");
    }

    #[test]
    fn an_overnight_window_runs_into_the_next_morning() {
        use RuleWeekday::{Fri, Mon, Sat, Sun, Tue};
        let w = window(&[Fri], "22:00", "06:00");
        assert!(w.contains(Fri, 22 * 60));
        assert!(w.contains(Fri, 23 * 60 + 59));
        assert!(
            w.contains(Sat, 5 * 60 + 59),
            "Friday night is still going on Saturday"
        );
        assert!(!w.contains(Sat, 6 * 60));
        assert!(
            !w.contains(Fri, 5 * 60),
            "Friday morning belongs to Thursday night"
        );
        assert!(!w.contains(Sat, 22 * 60), "Saturday evening is not listed");
        // Sunday night into Monday wraps the week.
        let sunday = window(&[Sun], "22:00", "06:00");
        assert!(sunday.contains(Mon, 3 * 60));
        assert!(!sunday.contains(Tue, 3 * 60));
    }

    #[test]
    fn the_end_of_the_day_is_inclusive_of_the_last_minute() {
        let w = window(&[RuleWeekday::Sat], "00:00", "24:00");
        assert!(w.contains(RuleWeekday::Sat, 0));
        assert!(w.contains(RuleWeekday::Sat, 1439));
        assert!(!w.contains(RuleWeekday::Sun, 0));
    }

    #[test]
    fn empty_or_malformed_windows_never_match() {
        let same = window(&[RuleWeekday::Mon], "09:00", "09:00");
        assert!(!same.contains(RuleWeekday::Mon, 9 * 60));
        let bad = window(&[RuleWeekday::Mon], "9am", "5pm");
        assert!(!bad.contains(RuleWeekday::Mon, 12 * 60));
        let no_days = window(&[], "09:00", "18:00");
        assert!(!no_days.contains(RuleWeekday::Mon, 12 * 60));
    }

    #[test]
    fn days_read_as_ranges() {
        use RuleWeekday::{Fri, Mon, Sat, Sun, Thu, Tue, Wed};
        assert_eq!(describe_days(&[Mon, Tue, Wed, Thu, Fri]), "Mon–Fri");
        assert_eq!(describe_days(&[Sat, Sun]), "Sat, Sun");
        assert_eq!(describe_days(&[Mon, Wed, Fri]), "Mon, Wed, Fri");
        assert_eq!(describe_days(&RuleWeekday::ALL), "Every day");
        assert_eq!(describe_days(&[]), "");
    }

    #[test]
    fn rules_describe_themselves() {
        let mut rules = AccessRules::new("Europe/Berlin", RuleAction::RequireApproval);
        rules.windows.push(window(
            &[
                RuleWeekday::Mon,
                RuleWeekday::Tue,
                RuleWeekday::Wed,
                RuleWeekday::Thu,
                RuleWeekday::Fri,
            ],
            "09:00",
            "18:00",
        ));
        assert_eq!(
            rules.describe(),
            "Mon–Fri 09:00–18:00 allow; otherwise require approval (Europe/Berlin)"
        );
    }

    #[test]
    fn actions_order_by_restriction() {
        assert!(RuleAction::Allow < RuleAction::RequireApproval);
        assert!(RuleAction::RequireApproval < RuleAction::Deny);
        assert_eq!(RuleAction::default(), RuleAction::Deny);
    }

    #[test]
    fn rules_round_trip_through_json_and_fail_closed_when_incomplete() {
        let stored = serde_json::json!({
            "timezone": "UTC",
            "windows": [{"days": ["mon"], "start": "09:00", "end": "17:00", "action": "allow"}],
            "outside": "require_approval",
            "approval": {"request_expiry_seconds": 900}
        });
        let rules: AccessRules = serde_json::from_value(stored).unwrap();
        assert_eq!(rules.outside, RuleAction::RequireApproval);
        assert_eq!(rules.approval.request_expiry_seconds, Some(900));
        assert!(rules.approval.approver_user_ids.is_empty());

        let bare: AccessRules =
            serde_json::from_value(serde_json::json!({"timezone": "UTC"})).unwrap();
        assert_eq!(bare.outside, RuleAction::Deny);
        assert!(bare.windows.is_empty());
    }
}
