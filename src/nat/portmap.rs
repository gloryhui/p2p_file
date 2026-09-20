//! 主动端口映射：UPnP IGD / NAT-PMP / PCP。
//!
//! 能直接要到一个公网端口的话，成功率比打洞高得多，也不需要对方配合。
//! 这一层现在还是**空壳**，等 M3 再落地。

use std::net::SocketAddr;
use std::time::Duration;

use crate::error::Result;

/// 传输层协议。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// 一条外部映射。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortMapping {
    /// 外部端口。
    pub external_port: u16,
    /// 本地端口。
    pub internal_port: u16,
    pub protocol: Protocol,
    /// 租期。到期前要续，否则映射会被回收。
    pub lifetime: Duration,
}

/// 主动向网关申请一个外部端口映射。
///
/// 返回 `Ok(None)` 表示当前网络环境没有可用的映射机制（网关不支持，
/// 或者不在 NAT 后面），调用方应当退回打洞 / 中继。
///
/// TODO(M3)：接入 `igd`（UPnP IGD）与 NAT-PMP/PCP 实现，顺序建议
///
/// 1. NAT-PMP / PCP：协议简单，家用路由器支持面也不小；
/// 2. UPnP IGD：支持最广但实现最啰嗦；
/// 3. 都不行就放弃，走打洞。
pub async fn try_map_port(
    _internal: SocketAddr,
    _protocol: Protocol,
    _lifetime: Duration,
) -> Result<Option<PortMapping>> {
    tracing::debug!("端口映射功能尚未实现（M3），跳过");
    Ok(None)
}

/// 当前是否具备主动映射能力。空壳阶段恒为 `false`。
pub fn is_supported() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn 未实现时返回_none_而不是报错() {
        let result = try_map_port(
            "0.0.0.0:0".parse().unwrap(),
            Protocol::Udp,
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        assert!(result.is_none(), "空壳阶段应安静地返回 None，让上层走兜底");
        assert!(!is_supported());
    }
}
