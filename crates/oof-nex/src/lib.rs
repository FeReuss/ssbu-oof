//! Wire formats spoken by NEX 4.x game clients (Super Smash Bros. Ultimate 13.0.5 uses NEX 4.6.13).
//!
//! Pure codecs, no I/O: the server crate owns sockets and state. Every format here is documented in
//! `docs/re/` together with the evidence it was derived from.

pub mod kerberos;
pub mod prudp;
pub mod rmc;
pub mod stream;

pub use stream::{Error, Reader, Writer};
