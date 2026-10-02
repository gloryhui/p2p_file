//! Authenticated, bounded UDP fallback. The relay never terminates QUIC or parses business data.
pub mod client;
pub mod server;
mod wire;

pub const RELAY_FALLBACK_DELAY: std::time::Duration = std::time::Duration::from_millis(2500);
pub const RELAY_BIND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
pub const RELAY_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(18);

#[cfg(test)]
pub(crate) mod tests;
