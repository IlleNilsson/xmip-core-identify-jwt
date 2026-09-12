#![forbid(unsafe_code)]
//! Identify by jwt: reads a bearer token's subject, unverified; an identifier at the transport
//! and message layers whose claim is passed.
//!
//! Declared and not yet written: `architecture.toml` carries the maturity. When it
//! is, it implements `TransportIdentifier` and `MessageIdentifier` (ADR-0050).
