//! 用多次 STUN 观测结果判断 NAT 的映射行为。
//!
//! 这一步决定了打洞有没有戏：
//!
//! - **端点无关映射（EIM）**：同一本地端口无论访问谁，NAT 都分配同一个公网端口。
//!   打洞成功率最高，STUN 问出来的地址可以直接给对方。
//! - **地址相关映射（ADM）**：换个目标 IP 就换一个公网端口，但同一目标 IP 下
//!   端口稳定。还能打，但要先用同一个服务器探出针对对方 IP 的映射。
//! - **地址端口相关映射（APDM，俗称对称型）**：换个目标端口也换映射，
//!   且分配规律不可知。基本只能靠端口预测或者中继。
//!
//! 注意：这里只判**映射**行为，没判**过滤**行为。完整判定（RFC 5780）还需要
//! 用 CHANGE-REQUEST 让服务器从另一个 IP/端口回包，看能不能收到——那需要
//! 服务器配合，属于 M3 的事。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::error::Result;
use crate::nat::stun::{StunResult, query_binding_with};

/// 一次 STUN 观测。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StunObservation {
    /// 被查询的 STUN 服务器地址。
    pub server: SocketAddr,
    /// 服务器看到的我们。
    pub mapped_addr: SocketAddr,
}

impl StunObservation {
    pub fn new(server: SocketAddr, mapped_addr: SocketAddr) -> Self {
        Self {
            server,
            mapped_addr,
        }
    }

    pub fn from_result(server: SocketAddr, result: &StunResult) -> Self {
        Self::new(server, result.mapped_addr)
    }
}

/// NAT 映射行为。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MappingBehavior {
    /// 端点无关：换个目标端口，映射不变。
    EndpointIndependent,
    /// 地址相关：目标 IP 相同则映射不变，换 IP 就变。
    AddressDependent,
    /// 地址端口相关（对称型）：换个目标端口映射就变。
    AddressAndPortDependent,
    /// 观测样本不足以判断。
    Unknown,
}

impl MappingBehavior {
    /// 这种 NAT 下直接打洞有没有希望。
    pub fn is_punchable(self) -> bool {
        matches!(self, Self::EndpointIndependent | Self::AddressDependent)
    }
}

/// 由若干观测推断映射行为。
///
/// 判定顺序：先看映射是否始终不变，再看变化是否只发生在跨 IP 时。
pub fn classify_mapping(observations: &[StunObservation]) -> MappingBehavior {
    // 一次观测什么都证明不了，别给出过于乐观的结论。
    if observations.len() < 2 {
        return MappingBehavior::Unknown;
    }

    // 所有观测的映射地址完全一致 → EIM。
    let first = observations[0].mapped_addr;
    if observations.iter().all(|o| o.mapped_addr == first) {
        return MappingBehavior::EndpointIndependent;
    }

    // 映射变过。按目标 IP 分组，看同组内是否稳定。
    let mut by_ip: HashMap<std::net::IpAddr, HashSet<SocketAddr>> = HashMap::new();
    for observation in observations {
        by_ip
            .entry(observation.server.ip())
            .or_default()
            .insert(observation.mapped_addr);
    }

    // 同一个目标 IP 下出现多个不同映射 → 换个目标端口就换映射，对称型。
    if by_ip.values().any(|mappings| mappings.len() > 1) {
        return MappingBehavior::AddressAndPortDependent;
    }

    // 各组内部都稳定，只有跨 IP 才变 → ADM。
    // 到这里组数必然 >= 2，否则前面「全部一致」那一步已经返回了。
    MappingBehavior::AddressDependent
}

/// 对一个或多个 STUN 服务器做观测。
///
/// 关键点：**所有查询共用同一个 socket**。换个 socket 就是换个本地端口，
/// 也就换了一个 NAT 映射，观测结果之间没法比较。
pub async fn observe(
    socket: &UdpSocket,
    servers: &[SocketAddr],
    timeout: Duration,
) -> Result<Vec<StunObservation>> {
    let mut observations = Vec::with_capacity(servers.len());
    for server in servers {
        match query_binding_with(socket, *server, timeout).await {
            Ok(result) => observations.push(StunObservation::from_result(*server, &result)),
            Err(err) => {
                tracing::warn!(%server, error = %err, "STUN 观测失败，跳过该服务器");
            }
        }
    }
    Ok(observations)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(server: &str, mapped: &str) -> StunObservation {
        StunObservation::new(server.parse().unwrap(), mapped.parse().unwrap())
    }

    #[test]
    fn 映射一致判为端点无关() {
        let observations = vec![
            obs("203.0.113.1:3478", "198.51.100.7:40000"),
            obs("203.0.113.2:3478", "198.51.100.7:40000"),
            obs("203.0.113.1:3479", "198.51.100.7:40000"),
        ];
        assert_eq!(
            classify_mapping(&observations),
            MappingBehavior::EndpointIndependent
        );
    }

    #[test]
    fn 换_ip_才变判为地址相关() {
        let observations = vec![
            obs("203.0.113.1:3478", "198.51.100.7:40000"),
            obs("203.0.113.1:3479", "198.51.100.7:40000"),
            obs("203.0.113.2:3478", "198.51.100.7:40001"),
        ];
        assert_eq!(
            classify_mapping(&observations),
            MappingBehavior::AddressDependent
        );
    }

    #[test]
    fn 换端口就变判为对称型() {
        let observations = vec![
            obs("203.0.113.1:3478", "198.51.100.7:40000"),
            obs("203.0.113.1:3479", "198.51.100.7:40001"),
            obs("203.0.113.2:3478", "198.51.100.7:40002"),
        ];
        assert_eq!(
            classify_mapping(&observations),
            MappingBehavior::AddressAndPortDependent
        );
    }

    #[test]
    fn 样本不足判为未知() {
        assert_eq!(classify_mapping(&[]), MappingBehavior::Unknown);
        assert_eq!(
            classify_mapping(&[obs("203.0.113.1:3478", "198.51.100.7:40000")]),
            MappingBehavior::Unknown,
            "只有一个目标 IP，分不出 EIM 和 ADM"
        );
    }

    #[test]
    fn 可打洞性判定() {
        assert!(MappingBehavior::EndpointIndependent.is_punchable());
        assert!(MappingBehavior::AddressDependent.is_punchable());
        assert!(!MappingBehavior::AddressAndPortDependent.is_punchable());
        assert!(!MappingBehavior::Unknown.is_punchable());
    }

    #[test]
    fn 公网映射与服务器同_ip_时也算发现() {
        // 两个观测落在同一个 IP 的不同端口，映射不同 → 对称型。
        let observations = vec![
            obs("203.0.113.1:3478", "198.51.100.7:40000"),
            obs("203.0.113.1:3479", "198.51.100.7:40001"),
        ];
        assert_eq!(
            classify_mapping(&observations),
            MappingBehavior::AddressAndPortDependent
        );
    }
}
