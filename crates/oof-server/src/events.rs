//! Timed game events (Utility 110/11 `GetGameEvents`): online tourneys and similar, defined by the operator in
//! `[[events]]` (config). Wire layout and the keys the game reads: docs/re/protocols.md, "Game events".

use oof_nex::stream::{DateTime, Variant, Writer};
use serde::Deserialize;
use std::collections::BTreeMap;
use toml::value::{Datetime, Offset};

/// One `GameEvent`. Field names follow what the game does with each field where that is known.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GameEvent {
    /// First `u32` (copied as the event's ID).
    pub id: u32,
    /// Second `u32`: a category bitmask; game code keeps the events whose mask shares a bit with the one it asks for.
    pub kinds: u32,
    /// The `u16`.
    #[serde(default)]
    pub flags: u16,
    /// First String (shown as the title, at most 63 characters).
    #[serde(default)]
    pub title: String,
    /// Second String (at most 63 characters).
    #[serde(default)]
    pub text: String,
    /// The four DateTimes in wire order (UTC).
    pub times: [Datetime; 4],
    /// `Map<String, Variant>`: integers, booleans, strings or times.
    #[serde(default)]
    pub params: BTreeMap<String, Param>,
    /// `Map<String, List<Variant>>`.
    #[serde(default)]
    pub lists: BTreeMap<String, Vec<Param>>,
    #[serde(default)]
    pub periods: Vec<Period>,
}

/// One `GameEventPeriod`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Period {
    pub id: u32,
    #[serde(default)]
    pub kind: u32,
    pub start: Datetime,
    pub end: Datetime,
    #[serde(default)]
    pub params: BTreeMap<String, Param>,
    #[serde(default)]
    pub lists: BTreeMap<String, Vec<Param>>,
    /// The trailing `u32`.
    #[serde(default)]
    pub value: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Param {
    Int(i64),
    Bool(bool),
    Text(String),
    Time(Datetime),
}

/// A TOML date-time as a NEX DateTime; only UTC (`Z` or no offset) and full dates are accepted.
pub fn nex_time(t: &Datetime) -> Result<DateTime, String> {
    let date = t.date.ok_or_else(|| format!("{t}: a date is required"))?;
    if !matches!(t.offset, None | Some(Offset::Z)) {
        return Err(format!("{t}: give event times in UTC (Z)"));
    }
    let (h, m, s) = t.time.map_or((0, 0, 0), |x| (x.hour, x.minute, x.second.unwrap_or(0)));
    Ok(DateTime(
        u64::from(s)
            | u64::from(m) << 6
            | u64::from(h) << 12
            | u64::from(date.day) << 17
            | u64::from(date.month) << 22
            | u64::from(date.year) << 26,
    ))
}

impl Param {
    fn variant(&self) -> Result<Variant, String> {
        Ok(match self {
            Param::Int(x) => Variant::I64(*x),
            Param::Bool(x) => Variant::Bool(*x),
            Param::Text(x) => Variant::String(x.clone()),
            Param::Time(x) => Variant::DateTime(nex_time(x)?),
        })
    }
}

fn maps(w: &mut Writer, params: &BTreeMap<String, Param>, lists: &BTreeMap<String, Vec<Param>>) -> Result<(), String> {
    w.u32(params.len() as u32);
    for (k, v) in params {
        w.string(k).variant(&v.variant()?);
    }
    w.u32(lists.len() as u32);
    for (k, vs) in lists {
        w.string(k).u32(vs.len() as u32);
        for v in vs {
            w.variant(&v.variant()?);
        }
    }
    Ok(())
}

impl GameEvent {
    /// Check every time and value once, at startup, so a bad config fails loudly instead of per request.
    pub fn validate(&self) -> Result<(), String> {
        self.write(&mut Writer::new()).map_err(|e| format!("event {}: {e}", self.id))
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), String> {
        let times = self.times.iter().map(nex_time).collect::<Result<Vec<_>, _>>()?;
        let mut out = Ok(());
        w.structure(0, |w| {
            w.u32(self.id).u32(self.kinds).u16(self.flags).string(&self.title).string(&self.text);
            for t in &times {
                w.u64(t.0);
            }
            out = maps(w, &self.params, &self.lists).and_then(|()| {
                w.u32(self.periods.len() as u32);
                self.periods.iter().try_for_each(|p| p.write(w))
            });
        });
        out
    }
}

impl Period {
    fn write(&self, w: &mut Writer) -> Result<(), String> {
        let (start, end) = (nex_time(&self.start)?, nex_time(&self.end)?);
        let mut out = Ok(());
        w.structure(0, |w| {
            w.u32(self.id).u32(self.kind).u64(start.0).u64(end.0);
            out = maps(w, &self.params, &self.lists);
            w.u32(self.value);
        });
        out
    }
}

/// `List<GameEvent>` for 110/11.
pub fn list(events: &[GameEvent]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(events.len() as u32);
    for e in events {
        e.write(&mut w).expect("events are validated at startup");
    }
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oof_nex::stream::Reader;

    #[test]
    fn event_wire_layout() {
        let e: GameEvent = toml::from_str(
            r#"
            id = 7
            kinds = 4
            title = "Cup"
            times = [2026-10-25T10:20:30Z, 2026-10-26T00:00:00Z, 2026-10-25T00:00:00Z, 2026-10-27T00:00:00Z]
            params = { time_sec = 180, team = false, url1 = "x" }
            lists = { item_flags = [1, 2] }
            [[periods]]
            id = 1
            start = 2026-10-25T00:00:00Z
            end = 2026-10-25T01:00:00Z
            value = 9
            "#,
        )
        .unwrap();
        let bytes = list(std::slice::from_ref(&e));
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u32().unwrap(), 1);
        let (_, mut s) = r.structure().unwrap();
        assert_eq!((s.u32().unwrap(), s.u32().unwrap(), s.u16().unwrap()), (7, 4, 0));
        assert_eq!((s.string().unwrap(), s.string().unwrap()), ("Cup".into(), String::new()));
        assert_eq!(DateTime(s.u64().unwrap()), DateTime::from_unix(1_792_923_630)); // 2026-10-25T10:20:30Z
        for _ in 0..3 {
            s.u64().unwrap();
        }
        assert_eq!(s.u32().unwrap(), 3);
        let params: Vec<_> = (0..3).map(|_| (s.string().unwrap(), s.variant().unwrap())).collect();
        assert_eq!(params[0], ("team".into(), Variant::Bool(false)));
        assert_eq!(params[1], ("time_sec".into(), Variant::I64(180)));
        assert_eq!(s.u32().unwrap(), 1);
        assert_eq!(s.string().unwrap(), "item_flags");
        assert_eq!(s.list(|r| r.variant()).unwrap(), [Variant::I64(1), Variant::I64(2)]);
        assert_eq!(s.u32().unwrap(), 1);
        let (_, mut p) = s.structure().unwrap();
        assert_eq!((p.u32().unwrap(), p.u32().unwrap()), (1, 0));
        p.u64().unwrap();
        p.u64().unwrap();
        assert_eq!((p.u32().unwrap(), p.u32().unwrap(), p.u32().unwrap(), p.remaining()), (0, 0, 9, 0));
        assert_eq!(s.remaining(), 0);
        let local: Datetime = "2026-10-25T10:00:00-03:00".parse().unwrap();
        assert!(nex_time(&local).is_err());
    }
}
