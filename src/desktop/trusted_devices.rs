//! Local, one-way identity grants. Display metadata never participates in authorization.
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::identity::NodeId;

use super::config::ConfigError;

pub const MAX_TRUSTED_DEVICES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedDevice {
    pub node_id: String,
    pub display_name: String,
    pub last_short_id: Option<String>,
    pub trusted_at: u64,
    pub updated_at: u64,
}

impl TrustedDevice {
    pub fn new(peer: NodeId, display_name: String, last_short_id: Option<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            node_id: peer.to_hex(),
            display_name,
            last_short_id,
            trusted_at: now,
            updated_at: now,
        }
    }
}

pub fn validate(devices: &[TrustedDevice]) -> Result<(), ConfigError> {
    if devices.len() > MAX_TRUSTED_DEVICES {
        return Err(ConfigError::Invalid("可信设备最多 128 个".into()));
    }
    let mut identities = HashSet::new();
    for device in devices {
        let id = NodeId::from_hex(&device.node_id)
            .map_err(|_| ConfigError::Invalid("可信设备必须使用完整 NodeId".into()))?;
        if device.node_id != id.to_hex() || !identities.insert(id) {
            return Err(ConfigError::Invalid("可信设备身份非规范或重复".into()));
        }
        if device.display_name.trim().is_empty()
            || device.display_name.len() > 128
            || device.display_name.chars().any(char::is_control)
            || device.updated_at < device.trusted_at
        {
            return Err(ConfigError::Invalid("可信设备展示信息无效".into()));
        }
        if let Some(short) = &device.last_short_id {
            crate::discovery::short_id::ShortId::normalize(short)
                .map_err(|_| ConfigError::Invalid("可信设备历史 Short ID 无效".into()))?;
        }
    }
    Ok(())
}

pub fn contains(devices: &[TrustedDevice], peer: NodeId) -> bool {
    devices.iter().any(|device| device.node_id == peer.to_hex())
}

/// Gregorian date from Unix seconds (UTC); metadata only.
pub fn date(seconds: u64) -> String {
    let days = (seconds / 86_400).min(2_932_896) as i64 + 719_468;
    let era = days / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_is_the_only_key_and_metadata_cannot_grant_or_duplicate_trust() {
        let peer = crate::identity::Identity::generate().node_id();
        let other = crate::identity::Identity::generate().node_id();
        let mut device = TrustedDevice::new(peer, "same name".into(), Some("100000124".into()));
        assert!(validate(&[]).is_ok());
        assert!(validate(&[device.clone()]).is_ok());
        assert!(!contains(&[device.clone()], other));
        device.last_short_id = Some("100000125".into());
        assert!(contains(&[device.clone()], peer));
        assert!(validate(&[device.clone(), device.clone()]).is_err());
        device.node_id = "100000125".into();
        assert!(validate(&[device]).is_err());
    }
    #[test]
    fn metadata_validation_and_dates() {
        let peer = crate::identity::Identity::generate().node_id();
        for name in ["", "\n", "device\0"] {
            assert!(validate(&[TrustedDevice::new(peer, name.into(), None)]).is_err());
        }
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_791_072_000), "2026-10-04");
    }
}
