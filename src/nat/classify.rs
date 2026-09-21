//! 用多次 STUN 观测结果判断 NAT 的映射行为。
//!
//! 这一步只描述 mapping behavior，不能单独决定打洞成败；filtering behavior
//! 必须另外测量。
//!
//! - **端点无关映射（EIM）**：同一本地端口无论访问谁，NAT 都分配同一个公网端口。
//!   mapping 角度较有利，但仍不能替代 filtering 证据。
//! - **地址相关映射（ADM）**：换个目标 IP 就换一个公网端口，但同一目标 IP 下
//!   端口稳定。它只是条件性 mapping 结论，不能单独宣称可以打洞。
//! - **地址端口相关映射（APDM，俗称对称型）**：换个目标端口也换映射，
//!   且分配规律不可知。基本只能靠端口预测或者中继。
//!
//! RFC 5780 的 OTHER-ADDRESS 用于 mapping 三点 probing；当前不把 CHANGE-REQUEST
//! 的回包可达性当作已测的 filtering behavior。

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::error::Result;
use crate::nat::stun::{StunResult, query_binding_with};

/// RFC 5780 mapping probing 的证据等级。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MappingEvidence {
    /// RFC 5780 行为发现已经取得足够证据；EIM 可以在 Test II 短路。
    Rfc5780,
    /// STUN 服务器没有提供可用的 OTHER-ADDRESS，或备用目标无法完成探测。
    InsufficientEvidence,
}

impl MappingEvidence {
    pub fn describe(self) -> &'static str {
        match self {
            Self::Rfc5780 => "RFC 5780 行为发现证据充分",
            Self::InsufficientEvidence => {
                "证据不足（服务器不支持 RFC 5780 行为发现或备用探测失败）"
            }
        }
    }
}

/// Filtering behavior 单独建模；当前实现只测 mapping，不声称测过 filtering。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FilteringBehavior {
    NotMeasured,
}

impl FilteringBehavior {
    pub fn describe(self) -> &'static str {
        match self {
            Self::NotMeasured => "未测量（当前只测 mapping）",
        }
    }
}

/// 一次 RFC 5780 mapping probing 的报告。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingProbe {
    /// 实际发送过 Binding 的目标及其映射结果。
    pub observations: Vec<StunObservation>,
    /// 第一次响应给出的备用目标；没有 OTHER-ADDRESS 时为 None。
    pub other_address: Option<SocketAddr>,
    pub mapping: MappingBehavior,
    pub evidence: MappingEvidence,
    pub filtering: FilteringBehavior,
}

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
    /// 给人看的中文描述。全项目只有这一处措辞，日志、`stun` 命令、
    /// 文档里说的必须是同一句话。
    pub fn describe(self) -> &'static str {
        match self {
            Self::EndpointIndependent => "端点无关（mapping 有利，但 filtering 未测）",
            Self::AddressDependent => "地址相关（仅在 RFC 5780 证据充分时成立，不能单独保证打洞）",
            Self::AddressAndPortDependent => "地址端口相关/对称型（mapping 对打洞不利）",
            Self::Unknown => "未知（证据不足）",
        }
    }

    /// 仅表示 mapping 是否值得继续尝试，绝不等价于最终 punchability。
    pub fn punchable(self) -> bool {
        matches!(self, Self::EndpointIndependent)
    }
}

impl MappingBehavior {
    /// 兼容旧调用点；Filtering 未测量时不把 ADM 当作无条件可打洞。
    pub fn is_punchable(self) -> bool {
        self.punchable()
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

    let distinct_ips: std::collections::HashSet<_> = observations
        .iter()
        .map(|observation| observation.server.ip())
        .collect();
    // 只有跨过至少两个目标 IP，且映射仍不变，才有证据称为 EIM。
    // 同一目标的重复查询不能区分 EIM 与 ADM。
    let first = observations[0].mapped_addr;
    if distinct_ips.len() >= 2 && observations.iter().all(|o| o.mapped_addr == first) {
        return MappingBehavior::EndpointIndependent;
    }

    // RFC 5780 的同 IP 不同端口样本，是区分 ADM 与 APDM 的必要证据。
    let mut same_ip_different_port = false;
    for (index, left) in observations.iter().enumerate() {
        for right in observations.iter().skip(index + 1) {
            if left.server.ip() == right.server.ip() && left.server.port() != right.server.port() {
                same_ip_different_port = true;
                if left.mapped_addr != right.mapped_addr {
                    return MappingBehavior::AddressAndPortDependent;
                }
            }
        }
    }
    if !same_ip_different_port || distinct_ips.len() < 2 {
        return MappingBehavior::Unknown;
    }

    // 同一目标 IP 的端口变化不改映射，但换目标 IP 后改了映射 → ADM。
    if observations
        .iter()
        .any(|observation| observation.mapped_addr != first)
    {
        return MappingBehavior::AddressDependent;
    }

    // 走到这里说明有跨 IP 观测，但没有足够变化证明具体行为。
    MappingBehavior::Unknown
}

/// 按 RFC 5780 §4.3 的顺序进行 mapping probing。
///
/// Test I 访问 primary；Test II 访问 alternate IP + primary port。若两次映射
/// 相同，已经足以判定 EIM，不再发送 Test III。只有 Test II 改变映射时，才
/// 访问 alternate IP + alternate port，并据此区分 ADM 与 APDM。
pub async fn probe_rfc5780(
    socket: &UdpSocket,
    primary: SocketAddr,
    timeout: Duration,
) -> Result<MappingProbe> {
    let first = query_binding_with(socket, primary, timeout).await?;
    let other_address = first.other_address;
    let mut observations = vec![StunObservation::from_result(primary, &first)];

    // RFC 5780 允许在 Test I 发现映射没有发生时，直接报告 effective EIM。
    if first.mapped_addr == socket.local_addr()? {
        return Ok(MappingProbe {
            observations,
            other_address,
            mapping: MappingBehavior::EndpointIndependent,
            evidence: MappingEvidence::Rfc5780,
            filtering: FilteringBehavior::NotMeasured,
        });
    }

    let Some(other) = other_address else {
        return Ok(MappingProbe {
            observations,
            other_address,
            mapping: MappingBehavior::Unknown,
            evidence: MappingEvidence::InsufficientEvidence,
            filtering: FilteringBehavior::NotMeasured,
        });
    };

    if !valid_other_address(primary, other) {
        tracing::warn!(%primary, %other, "STUN OTHER-ADDRESS 不是有效的 RFC 5780 alternate topology");
        return Ok(MappingProbe {
            observations,
            other_address,
            mapping: MappingBehavior::Unknown,
            evidence: MappingEvidence::InsufficientEvidence,
            filtering: FilteringBehavior::NotMeasured,
        });
    }

    let alternate_ip_primary_port = SocketAddr::new(other.ip(), primary.port());
    let second = match query_binding_with(socket, alternate_ip_primary_port, timeout).await {
        Ok(result) => result,
        Err(err) => {
            tracing::warn!(target = %alternate_ip_primary_port, error = %err, "RFC 5780 Test II 探测失败");
            return Ok(MappingProbe {
                mapping: MappingBehavior::Unknown,
                evidence: MappingEvidence::InsufficientEvidence,
                filtering: FilteringBehavior::NotMeasured,
                observations,
                other_address,
            });
        }
    };
    observations.push(StunObservation::from_result(
        alternate_ip_primary_port,
        &second,
    ));

    // RFC 5780 §4.3: Test II 与 Test I 相同即结束，Test III 不需要成功甚至
    // 不应该被发送；这也是 EIM 在备用端口不可达时仍可确认的关键。
    if second.mapped_addr == first.mapped_addr {
        return Ok(MappingProbe {
            observations,
            other_address,
            mapping: MappingBehavior::EndpointIndependent,
            evidence: MappingEvidence::Rfc5780,
            filtering: FilteringBehavior::NotMeasured,
        });
    }

    let third = match query_binding_with(socket, other, timeout).await {
        Ok(result) => result,
        Err(err) => {
            tracing::warn!(target = %other, error = %err, "RFC 5780 Test III 探测失败");
            return Ok(MappingProbe {
                mapping: MappingBehavior::Unknown,
                evidence: MappingEvidence::InsufficientEvidence,
                filtering: FilteringBehavior::NotMeasured,
                observations,
                other_address,
            });
        }
    };
    observations.push(StunObservation::from_result(other, &third));

    Ok(MappingProbe {
        mapping: if third.mapped_addr == second.mapped_addr {
            MappingBehavior::AddressDependent
        } else {
            MappingBehavior::AddressAndPortDependent
        },
        evidence: MappingEvidence::Rfc5780,
        filtering: FilteringBehavior::NotMeasured,
        observations,
        other_address,
    })
}

fn valid_other_address(primary: SocketAddr, other: SocketAddr) -> bool {
    !other.ip().is_unspecified()
        && other.port() != 0
        && primary.is_ipv4() == other.is_ipv4()
        && other.ip() != primary.ip()
        && other.port() != primary.port()
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
    fn rfc5780三点样本判为地址相关() {
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
    fn 跨_ip_单样本不足以判定_adm() {
        let observations = vec![
            obs("203.0.113.1:3478", "198.51.100.7:40000"),
            obs("203.0.113.2:3478", "198.51.100.7:40001"),
            obs("203.0.113.3:3478", "198.51.100.7:40002"),
        ];
        assert_eq!(classify_mapping(&observations), MappingBehavior::Unknown);
    }

    #[test]
    fn rfc5780三点样本判为地址端口相关() {
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
        assert!(!MappingBehavior::AddressDependent.is_punchable());
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

    async fn probe_with_mappings(mapped: [SocketAddr; 3], serve_test_iii: bool) -> MappingProbe {
        use crate::nat::stun::{Attribute, Message, MessageClass, Method};

        let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary.local_addr().unwrap();
        let alternate_ip_primary_port = UdpSocket::bind(SocketAddr::new(
            "127.0.0.2".parse().unwrap(),
            primary_addr.port(),
        ))
        .await
        .unwrap();
        let alternate_ip_alternate_port = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let alternate_addr = alternate_ip_alternate_port.local_addr().unwrap();

        let task = tokio::spawn(async move {
            let sockets = [
                primary,
                alternate_ip_primary_port,
                alternate_ip_alternate_port,
            ];
            let count = if serve_test_iii { 3 } else { 2 };
            for (index, socket) in sockets.into_iter().take(count).enumerate() {
                let mut buffer = [0u8; 1500];
                let (len, from) = socket.recv_from(&mut buffer).await.unwrap();
                let request = Message::decode(&buffer[..len]).unwrap();
                let mut attributes = vec![Attribute::XorMappedAddress(mapped[index])];
                if index == 0 {
                    attributes.push(Attribute::OtherAddress(alternate_addr));
                }
                let response = Message {
                    method: Method::Binding,
                    class: MessageClass::SuccessResponse,
                    transaction_id: request.transaction_id,
                    attributes,
                };
                socket.send_to(&response.encode(), from).await.unwrap();
            }
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let report = probe_rfc5780(&socket, primary_addr, Duration::from_secs(1))
            .await
            .unwrap();
        task.await.unwrap();
        report
    }

    #[tokio::test]
    async fn rfc5780_test_ii与_test_i相同则两步判定_eim() {
        let report = probe_with_mappings(
            [
                "198.51.100.7:40000".parse().unwrap(),
                "198.51.100.7:40000".parse().unwrap(),
                "198.51.100.7:49999".parse().unwrap(),
            ],
            false,
        )
        .await;

        assert_eq!(report.evidence, MappingEvidence::Rfc5780);
        assert_eq!(report.mapping, MappingBehavior::EndpointIndependent);
        assert_eq!(report.filtering, FilteringBehavior::NotMeasured);
        assert_eq!(report.observations.len(), 2);
    }

    #[tokio::test]
    async fn rfc5780_test_iii与_test_ii相同则判定_adm() {
        let report = probe_with_mappings(
            [
                "198.51.100.7:40000".parse().unwrap(),
                "198.51.100.7:40001".parse().unwrap(),
                "198.51.100.7:40001".parse().unwrap(),
            ],
            true,
        )
        .await;

        assert_eq!(report.evidence, MappingEvidence::Rfc5780);
        assert_eq!(report.mapping, MappingBehavior::AddressDependent);
        assert_eq!(report.observations.len(), 3);
    }

    #[tokio::test]
    async fn rfc5780_test_iii与_test_ii不同则判定_apdm() {
        let report = probe_with_mappings(
            [
                "198.51.100.7:40000".parse().unwrap(),
                "198.51.100.7:40001".parse().unwrap(),
                "198.51.100.7:40002".parse().unwrap(),
            ],
            true,
        )
        .await;

        assert_eq!(report.evidence, MappingEvidence::Rfc5780);
        assert_eq!(report.mapping, MappingBehavior::AddressAndPortDependent);
        assert_eq!(report.observations.len(), 3);
    }

    #[tokio::test]
    async fn test_i映射等于本地地址时直接判定有效_eim() {
        use crate::nat::stun::{Attribute, Message, MessageClass, Method};

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            let (len, from) = server.recv_from(&mut buffer).await.unwrap();
            let request = Message::decode(&buffer[..len]).unwrap();
            let response = Message {
                method: Method::Binding,
                class: MessageClass::SuccessResponse,
                transaction_id: request.transaction_id,
                attributes: vec![Attribute::XorMappedAddress(from)],
            };
            server.send_to(&response.encode(), from).await.unwrap();
        });

        let report = probe_rfc5780(&socket, server_addr, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(report.mapping, MappingBehavior::EndpointIndependent);
        assert_eq!(report.evidence, MappingEvidence::Rfc5780);
        assert_eq!(report.observations.len(), 1);
        assert_eq!(report.observations[0].mapped_addr, local_addr);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn 非法_other_address报告证据不足() {
        use crate::nat::stun::{Attribute, Message, MessageClass, Method};

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let invalid_other = server_addr;
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            let (len, from) = server.recv_from(&mut buffer).await.unwrap();
            let request = Message::decode(&buffer[..len]).unwrap();
            let response = Message {
                method: Method::Binding,
                class: MessageClass::SuccessResponse,
                transaction_id: request.transaction_id,
                attributes: vec![
                    Attribute::XorMappedAddress("198.51.100.7:40000".parse().unwrap()),
                    Attribute::OtherAddress(invalid_other),
                ],
            };
            server.send_to(&response.encode(), from).await.unwrap();
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let report = probe_rfc5780(&socket, server_addr, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(report.mapping, MappingBehavior::Unknown);
        assert_eq!(report.evidence, MappingEvidence::InsufficientEvidence);
        assert_eq!(report.observations.len(), 1);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn stun不提供_other_address时报告证据不足() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            let (len, from) = server.recv_from(&mut buffer).await.unwrap();
            let request = crate::nat::stun::Message::decode(&buffer[..len]).unwrap();
            let response = crate::nat::stun::Message {
                method: crate::nat::stun::Method::Binding,
                class: crate::nat::stun::MessageClass::SuccessResponse,
                transaction_id: request.transaction_id,
                attributes: vec![crate::nat::stun::Attribute::XorMappedAddress(
                    "198.51.100.7:40000".parse().unwrap(),
                )],
            };
            server.send_to(&response.encode(), from).await.unwrap();
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let report = probe_rfc5780(&socket, server_addr, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(report.mapping, MappingBehavior::Unknown);
        assert_eq!(report.evidence, MappingEvidence::InsufficientEvidence);
        assert_eq!(report.filtering, FilteringBehavior::NotMeasured);
        assert!(report.other_address.is_none());
        task.await.unwrap();
    }
}
