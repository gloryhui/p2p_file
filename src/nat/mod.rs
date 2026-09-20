//! NAT 穿透：STUN 查询、类型判定、打洞、端口映射。

pub mod classify;
pub mod portmap;
pub mod punch;
pub mod stun;

pub use classify::{MappingBehavior, StunObservation, classify_mapping};
pub use punch::{PunchConfig, PunchToken, simultaneous_open, simultaneous_open_any};
pub use stun::{StunResult, query_binding};
