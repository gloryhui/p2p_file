//! 局域网发现：用 mDNS 在同一个二层网络里互相看见。
//!
//! 局域网是最容易打通的场景（通常没有 NAT，或者 NAT 支持 hairpin），
//! 所以先把它做出来，能独立验证传输层和协议层。
//!
//! 服务类型用 `_p2pfile._udp.local.`，TXT 里带节点 ID。

use std::collections::HashMap;
use std::net::IpAddr;

use mdns_sd::{Receiver, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::protocol::PROTOCOL_VERSION;

/// mDNS 服务类型。
pub const SERVICE_TYPE: &str = "_p2pfile._udp.local.";
/// TXT 里的节点 ID 键。
pub const TXT_NODE_ID: &str = "id";
/// TXT 里的协议版本键。
pub const TXT_PROTOCOL: &str = "proto";

/// 局域网里发现的一个对端。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAnnouncement {
    pub node_id: NodeId,
    /// mDNS 实例名。
    pub instance: String,
    /// 主机名。
    pub host: String,
    /// 对端监听的 UDP 端口。
    pub port: u16,
    /// 对端的所有地址，IPv4 / IPv6 都可能有。
    pub addresses: Vec<IpAddr>,
}

impl PeerAnnouncement {
    /// 按优先级排好的候选地址。
    ///
    /// IPv6 优先：公网 IPv6 通常没有 NAT，直连最省事。同一族里非链路本地优先。
    pub fn sorted_addresses(&self) -> Vec<IpAddr> {
        let mut addresses = self.addresses.clone();
        addresses.sort_by_key(|ip| match ip {
            IpAddr::V6(v6) if v6.is_loopback() => 30,
            IpAddr::V6(v6) if v6.is_unicast_link_local() => 20,
            IpAddr::V6(_) => 0,
            IpAddr::V4(v4) if v4.is_loopback() => 40,
            IpAddr::V4(v4) if v4.is_link_local() => 20,
            IpAddr::V4(_) => 10,
        });
        addresses
    }
}

/// 从 mDNS 解析结果里读出我们的公告。
///
/// 缺少节点 ID 的记录直接忽略——那可能是别的程序碰巧用了同一个服务类型。
pub fn parse_announcement(resolved: &ResolvedService) -> Option<PeerAnnouncement> {
    let node_id_hex = resolved.txt_properties.get_property_val_str(TXT_NODE_ID)?;
    let node_id = NodeId::from_hex(node_id_hex).ok()?;

    // 协议版本对不上就先不当成可用对端，避免握手必然失败。
    if let Some(version) = resolved.txt_properties.get_property_val_str(TXT_PROTOCOL) {
        match version.parse::<u32>() {
            Ok(version) if version == PROTOCOL_VERSION => {}
            _ => return None,
        }
    }

    let mut addresses: Vec<IpAddr> = resolved
        .addresses
        .iter()
        .map(|scoped| scoped.to_ip_addr())
        .collect();
    addresses.sort();
    addresses.dedup();

    Some(PeerAnnouncement {
        node_id,
        instance: resolved.fullname.clone(),
        host: resolved.host.clone(),
        port: resolved.port,
        addresses,
    })
}

/// 枚举本机的非环回地址。
///
/// 拿不到任何地址时返回空列表，交给调用方决定（`()` 表示让 mDNS 自己看着办）。
pub fn local_ip_addresses() -> Vec<IpAddr> {
    match if_addrs::get_if_addrs() {
        Ok(interfaces) => {
            let mut addresses: Vec<IpAddr> = interfaces
                .into_iter()
                .filter(|interface| !interface.is_loopback() && interface.is_oper_up())
                .map(|interface| interface.ip())
                .collect();
            addresses.sort();
            addresses.dedup();
            addresses
        }
        Err(err) => {
            tracing::warn!(error = %err, "枚举网卡地址失败");
            Vec::new()
        }
    }
}

/// 局域网发现的服务端 + 客户端。
pub struct LanDiscovery {
    daemon: ServiceDaemon,
    node_id: NodeId,
}

impl LanDiscovery {
    /// 创建发现服务，并以 `port` 在局域网里公告自己。
    pub fn announce(node_id: NodeId, port: u16) -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(mdns_error)?;

        let instance = format!("p2pfile-{}", node_id.short());
        let host_name = format!("{instance}.local.");

        let mut properties = HashMap::new();
        properties.insert(TXT_NODE_ID.to_string(), node_id.to_hex());
        properties.insert(TXT_PROTOCOL.to_string(), PROTOCOL_VERSION.to_string());

        let addresses = local_ip_addresses();
        if addresses.is_empty() {
            tracing::warn!("没有枚举到可用的网卡地址，mDNS 公告可能不会被解析出来");
        }

        let info = if addresses.is_empty() {
            // `()` 表示「地址交给 mDNS 库自己判断」。
            ServiceInfo::new(SERVICE_TYPE, &instance, &host_name, (), port, properties)
                .map_err(mdns_error)?
        } else {
            ServiceInfo::new(
                SERVICE_TYPE,
                &instance,
                &host_name,
                addresses.as_slice(),
                port,
                properties,
            )
            .map_err(mdns_error)?
        }
        // 网卡地址变化时（比如切 WiFi）自动更新记录。
        .enable_addr_auto();

        daemon.register(info).map_err(mdns_error)?;
        tracing::info!(%instance, port, "已在局域网公告自己");

        Ok(Self { daemon, node_id })
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// 开始浏览同类型服务，返回事件流。
    pub fn browse(&self) -> Result<Receiver<ServiceEvent>> {
        self.daemon.browse(SERVICE_TYPE).map_err(mdns_error)
    }

    pub fn shutdown(&self) -> Result<()> {
        self.daemon.shutdown().map_err(mdns_error)?;
        Ok(())
    }
}

impl std::fmt::Debug for LanDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LanDiscovery")
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

fn mdns_error(err: mdns_sd::Error) -> Error {
    Error::Discovery(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 服务类型合法() {
        assert!(SERVICE_TYPE.ends_with(".local."));
        assert!(SERVICE_TYPE.starts_with('_'));
        // mDNS 服务类型的标签长度上限是 15 字节（不含下划线和点）。
        let label = SERVICE_TYPE
            .trim_start_matches('_')
            .split('.')
            .next()
            .unwrap();
        assert!(label.len() <= 15, "服务名标签过长: {label}");
    }

    #[test]
    fn 地址优先级_ipv6_优先于_ipv4() {
        let announcement = PeerAnnouncement {
            node_id: NodeId::from_hex("00000000000000000000000000000001").unwrap(),
            instance: "test".into(),
            host: "test.local.".into(),
            port: 9000,
            addresses: vec![
                "192.168.1.5".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
                "fe80::1".parse().unwrap(),
                "10.0.0.9".parse().unwrap(),
            ],
        };
        let sorted = announcement.sorted_addresses();
        assert_eq!(sorted[0], "2001:db8::1".parse::<IpAddr>().unwrap());
        // 最后应该是局域网 IPv4 或链路本地，总之不是一个随意的顺序。
        assert!(sorted.len() == 4);
    }

    #[test]
    fn 本机至少能枚举出地址或安静返回() {
        // 在 CI / 容器里可能一个地址都没有，所以只断言不 panic。
        let addresses = local_ip_addresses();
        assert!(
            addresses.iter().all(|ip| !ip.is_loopback()),
            "不该包含环回地址"
        );
    }
}
