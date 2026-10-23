//! NEX data streams: little-endian primitives plus the composite types every protocol uses.
//!
//! Switch profile (NEX 4.x): PIDs are 64-bit and every `Structure` carries a header
//! (`u8 version`, `u32 content length`).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The message ended before the value did.
    Eof,
    /// The bytes are not a valid value of the expected type.
    Invalid(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Eof => write!(f, "unexpected end of NEX stream"),
            Error::Invalid(what) => write!(f, "invalid NEX value: {what}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Upper bound for element counts read from the wire, so a hostile length cannot reserve gigabytes.
const MAX_ELEMENTS: usize = 1 << 16;

#[derive(Default, Debug, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn bytes(&mut self, data: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(data);
        self
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes(&[v])
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    pub fn f64(&mut self, v: f64) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    pub fn pid(&mut self, v: u64) -> &mut Self {
        self.u64(v)
    }

    /// `u16` length including the NUL terminator, then the bytes and the NUL.
    pub fn string(&mut self, s: &str) -> &mut Self {
        self.u16((s.len() + 1) as u16).bytes(s.as_bytes()).u8(0)
    }

    /// `Buffer`: `u32` length + bytes.
    pub fn buffer(&mut self, data: &[u8]) -> &mut Self {
        self.u32(data.len() as u32).bytes(data)
    }

    /// `qBuffer`: `u16` length + bytes.
    pub fn qbuffer(&mut self, data: &[u8]) -> &mut Self {
        self.u16(data.len() as u16).bytes(data)
    }

    /// `Result` (NEX error code; `0x00010001` is success).
    pub fn result(&mut self, code: u32) -> &mut Self {
        self.u32(code)
    }

    pub fn list<T>(&mut self, items: &[T], mut each: impl FnMut(&mut Self, &T)) -> &mut Self {
        self.u32(items.len() as u32);
        for item in items {
            each(self, item);
        }
        self
    }

    /// `Structure` with the NEX 3.5+ header: version byte and content length.
    pub fn structure(&mut self, version: u8, content: impl FnOnce(&mut Self)) -> &mut Self {
        self.u8(version).u32(0);
        let start = self.buf.len();
        content(self);
        let len = (self.buf.len() - start) as u32;
        self.buf[start - 4..start].copy_from_slice(&len.to_le_bytes());
        self
    }

    /// `AnyDataHolder`: class name, then the structure with two length prefixes.
    pub fn any_data(&mut self, class: &str, content: impl FnOnce(&mut Self)) -> &mut Self {
        self.string(class).u32(0).u32(0);
        let start = self.buf.len();
        content(self);
        let len = (self.buf.len() - start) as u32;
        self.buf[start - 8..start - 4].copy_from_slice(&(len + 4).to_le_bytes());
        self.buf[start - 4..start].copy_from_slice(&len.to_le_bytes());
        self
    }

    pub fn variant(&mut self, v: &Variant) -> &mut Self {
        match v {
            Variant::None => self.u8(0),
            Variant::I64(x) => self.u8(1).i64(*x),
            Variant::F64(x) => self.u8(2).f64(*x),
            Variant::Bool(x) => self.u8(3).bool(*x),
            Variant::String(x) => self.u8(4).string(x),
            Variant::DateTime(x) => self.u8(5).u64(x.0),
            Variant::U64(x) => self.u8(6).u64(*x),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Eof);
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("take returned N bytes"))
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }

    pub fn u16(&mut self) -> Result<u16> {
        self.array().map(u16::from_le_bytes)
    }

    pub fn u32(&mut self) -> Result<u32> {
        self.array().map(u32::from_le_bytes)
    }

    pub fn i32(&mut self) -> Result<i32> {
        self.array().map(i32::from_le_bytes)
    }

    pub fn u64(&mut self) -> Result<u64> {
        self.array().map(u64::from_le_bytes)
    }

    pub fn i64(&mut self) -> Result<i64> {
        self.array().map(i64::from_le_bytes)
    }

    pub fn f64(&mut self) -> Result<f64> {
        self.array().map(f64::from_le_bytes)
    }

    pub fn pid(&mut self) -> Result<u64> {
        self.u64()
    }

    pub fn string(&mut self) -> Result<String> {
        let len = self.u16()? as usize;
        let raw = self.take(len)?;
        let text = raw.strip_suffix(&[0]).unwrap_or(raw);
        String::from_utf8(text.to_vec()).map_err(|_| Error::Invalid("string is not UTF-8"))
    }

    pub fn buffer(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    pub fn qbuffer(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()? as usize;
        self.take(len)
    }

    pub fn list<T>(&mut self, mut each: impl FnMut(&mut Self) -> Result<T>) -> Result<Vec<T>> {
        let count = self.u32()? as usize;
        if count > MAX_ELEMENTS || count > self.remaining() {
            return Err(Error::Invalid("list length"));
        }
        (0..count).map(|_| each(self)).collect()
    }

    /// Reads a `Structure` header and returns (version, reader limited to its content).
    /// Content beyond what the caller reads is skipped, so newer client versions stay compatible.
    pub fn structure(&mut self) -> Result<(u8, Reader<'a>)> {
        let version = self.u8()?;
        let len = self.u32()? as usize;
        Ok((version, Reader::new(self.take(len)?)))
    }

    /// Reads an `AnyDataHolder` and returns (class name, reader over the held structure).
    pub fn any_data(&mut self) -> Result<(String, Reader<'a>)> {
        let class = self.string()?;
        let outer = self.u32()? as usize;
        let inner = self.u32()? as usize;
        if outer != inner + 4 {
            return Err(Error::Invalid("AnyDataHolder lengths"));
        }
        Ok((class, Reader::new(self.take(inner)?)))
    }

    pub fn variant(&mut self) -> Result<Variant> {
        Ok(match self.u8()? {
            0 => Variant::None,
            1 => Variant::I64(self.i64()?),
            2 => Variant::F64(self.f64()?),
            3 => Variant::Bool(self.bool()?),
            4 => Variant::String(self.string()?),
            5 => Variant::DateTime(DateTime(self.u64()?)),
            6 => Variant::U64(self.u64()?),
            _ => return Err(Error::Invalid("variant type")),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Variant {
    None,
    I64(i64),
    F64(f64),
    Bool(bool),
    String(String),
    DateTime(DateTime),
    U64(u64),
}

/// NEX `DateTime`: `second | minute << 6 | hour << 12 | day << 17 | month << 22 | year << 26`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct DateTime(pub u64);

impl DateTime {
    pub fn from_unix(secs: u64) -> Self {
        let days = (secs / 86_400) as i64;
        let rem = secs % 86_400;
        let (y, m, d) = civil_from_days(days);
        DateTime(
            (rem % 60)
                | ((rem / 60 % 60) << 6)
                | (rem / 3600) << 12
                | (d as u64) << 17
                | (m as u64) << 22
                | (y as u64) << 26,
        )
    }

    pub fn now() -> Self {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Self::from_unix(secs)
    }

    pub fn to_unix(self) -> u64 {
        let v = self.0;
        let days = days_from_civil((v >> 26) as i64, (v >> 22 & 15) as u32, (v >> 17 & 31) as u32);
        days as u64 * 86_400 + (v >> 12 & 31) * 3600 + (v >> 6 & 63) * 60 + (v & 63)
    }
}

// Howard Hinnant's civil calendar algorithms (public domain).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + (m <= 2) as i64, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - (m <= 2) as i64;
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_round_trip() {
        let mut w = Writer::new();
        w.string("prudps")
            .structure(1, |w| {
                w.u32(7).list(&[1u32, 2, 3], |w, v| {
                    w.u32(*v);
                });
            })
            .any_data("NullData", |w| {
                w.structure(0, |_| {});
            })
            .variant(&Variant::String("rule".into()));
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.string().unwrap(), "prudps");
        let (version, mut s) = r.structure().unwrap();
        assert_eq!((version, s.u32().unwrap()), (1, 7));
        assert_eq!(s.list(|r| r.u32()).unwrap(), vec![1, 2, 3]);
        let (class, mut held) = r.any_data().unwrap();
        assert_eq!(class, "NullData");
        assert_eq!(held.structure().unwrap().1.remaining(), 0);
        assert_eq!(r.variant().unwrap(), Variant::String("rule".into()));
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn string_wire_form() {
        let mut w = Writer::new();
        w.string("");
        assert_eq!(w.into_bytes(), [1, 0, 0]);
    }

    #[test]
    fn hostile_lengths_are_rejected() {
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff, 0xff]).list(|r| r.u8()), Err(Error::Invalid("list length")));
        assert_eq!(Reader::new(&[5, 0, b'a']).string(), Err(Error::Eof));
    }

    #[test]
    fn datetime_matches_known_value() {
        // 2026-10-23 12:34:56 UTC
        let dt = DateTime::from_unix(1_792_758_896);
        assert_eq!((dt.0 >> 26, dt.0 >> 22 & 15, dt.0 >> 17 & 31), (2026, 10, 23));
        assert_eq!((dt.0 >> 12 & 31, dt.0 >> 6 & 63, dt.0 & 63), (12, 34, 56));
        assert_eq!(dt.to_unix(), 1_792_758_896);
    }
}
