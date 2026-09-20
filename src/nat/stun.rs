//! 手写的 STUN（RFC 5389）最小实现：够用来问出「我在 NAT 外面长什么样」。
//!
//! 只实现不认证的 Binding 请求/响应。带 MESSAGE-INTEGRITY 的长效凭证机制
//! 这里不需要——我们只用 STUN 做地址发现，认证交给应用层握手。
//!
//! 报文格式：
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     Message Type          |         Message Length         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Transaction ID (96 bits)                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! 属性区是 TLV，value 补齐到 4 字节边界（长度字段记的是补齐**前**的长度）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::error::{Error, Result};

/// STUN 固定魔数。
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
/// 报文头长度。
pub const HEADER_LEN: usize = 20;
/// 事务 ID 长度。
pub const TRANSACTION_ID_LEN: usize = 12;

const METHOD_BINDING: u16 = 0x0001;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;
const ATTR_RESPONSE_ORIGIN: u16 = 0x802b;
const ATTR_OTHER_ADDRESS: u16 = 0x802c;

/// FINGERPRINT 属性的固定异或值（"STUN" 的 ASCII）。
const FINGERPRINT_XOR: u32 = 0x5354_554E;

/// FINGERPRINT 属性总长度：4 字节头 + 4 字节值。
const FINGERPRINT_LEN: usize = 8;

const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// 消息类别。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl MessageClass {
    fn code(self) -> u16 {
        match self {
            Self::Request => 0b00,
            Self::Indication => 0b01,
            Self::SuccessResponse => 0b10,
            Self::ErrorResponse => 0b11,
        }
    }

    fn from_code(code: u16) -> Self {
        match code & 0b11 {
            0b00 => Self::Request,
            0b01 => Self::Indication,
            0b10 => Self::SuccessResponse,
            _ => Self::ErrorResponse,
        }
    }
}

/// 我们只关心 Binding。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    Binding,
}

/// 一条属性。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Attribute {
    MappedAddress(SocketAddr),
    XorMappedAddress(SocketAddr),
    ResponseOrigin(SocketAddr),
    OtherAddress(SocketAddr),
    Software(String),
    /// 不认识的属性，原样保留。
    Unknown {
        kind: u16,
        value: Vec<u8>,
    },
}

/// 一条 STUN 消息。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
    pub method: Method,
    pub class: MessageClass,
    pub transaction_id: [u8; TRANSACTION_ID_LEN],
    pub attributes: Vec<Attribute>,
}

impl Message {
    /// 生成一个 Binding 请求。
    pub fn binding_request(transaction_id: [u8; TRANSACTION_ID_LEN]) -> Self {
        Self {
            method: Method::Binding,
            class: MessageClass::Request,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    /// 取 XOR-MAPPED-ADDRESS，没有就退回 MAPPED-ADDRESS。
    ///
    /// 现在几乎没有服务器只回 MAPPED-ADDRESS 了，但老设备上仍可能遇到。
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        self.attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::XorMappedAddress(addr) => Some(*addr),
                _ => None,
            })
            .or_else(|| {
                self.attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        Attribute::MappedAddress(addr) => Some(*addr),
                        _ => None,
                    })
            })
    }

    pub fn response_origin(&self) -> Option<SocketAddr> {
        self.attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::ResponseOrigin(addr) => Some(*addr),
                _ => None,
            })
    }

    pub fn other_address(&self) -> Option<SocketAddr> {
        self.attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::OtherAddress(addr) => Some(*addr),
                _ => None,
            })
    }

    pub fn software(&self) -> Option<&str> {
        self.attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::Software(text) => Some(text.as_str()),
                _ => None,
            })
    }

    /// 编码。
    ///
    /// 消息类型字段的位交错规则见 RFC 5389 §6：
    /// `type = (method & 0x000F) | ((method & 0x0070) << 1)
    ///         | ((method & 0x0F80) << 2) | ((class & 0x0002) << 7)
    ///         | ((class & 0x0001) << 4)`
    ///
    /// 所有消息都会自动带上 FINGERPRINT 作为最后一个属性：RFC 5389 §8.1 说
    /// 客户端 SHOULD 带，而且确实有服务器不收没指纹的请求。
    pub fn encode(&self) -> Vec<u8> {
        let method_code = match self.method {
            Method::Binding => METHOD_BINDING,
        };
        let class_code = self.class.code();
        let message_type = (method_code & 0x000F)
            | ((method_code & 0x0070) << 1)
            | ((method_code & 0x0F80) << 2)
            | ((class_code & 0x0002) << 7)
            | ((class_code & 0x0001) << 4);

        let mut attributes = Vec::new();
        for attribute in &self.attributes {
            encode_attribute(&mut attributes, attribute, &self.transaction_id);
        }

        let body_len = attributes.len() + FINGERPRINT_LEN;

        let mut out = Vec::with_capacity(HEADER_LEN + body_len);
        out.extend_from_slice(&message_type.to_be_bytes());
        out.extend_from_slice(&(body_len as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&self.transaction_id);
        out.extend_from_slice(&attributes);

        // 指纹覆盖「到目前为止」的全部字节，即含消息头、不含指纹属性本身。
        let fingerprint = crc32(&out) ^ FINGERPRINT_XOR;
        out.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&fingerprint.to_be_bytes());
        out
    }

    /// 解码。
    ///
    /// 如果报文带了 FINGERPRINT，会强制校验；校验不过直接报错，
    /// 不做「可能只是坏包，凑合解析」的处理。
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Stun(format!(
                "报文只有 {} 字节，短于 {HEADER_LEN} 字节头部",
                bytes.len()
            )));
        }

        let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        // 头两个 bit 必须是 0。
        if message_type & 0xC000 != 0 {
            return Err(Error::Stun("消息类型前两位应为 0".into()));
        }

        let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if !length.is_multiple_of(4) {
            return Err(Error::Stun(format!("属性区长度 {length} 不是 4 的倍数")));
        }
        if HEADER_LEN + length > bytes.len() {
            return Err(Error::Stun(format!(
                "声称有 {length} 字节属性，实际只剩 {} 字节",
                bytes.len() - HEADER_LEN
            )));
        }

        let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(Error::Stun(format!(
                "magic cookie 应为 {MAGIC_COOKIE:#010x}，实际 {cookie:#010x}"
            )));
        }

        verify_fingerprint(bytes, length)?;

        let mut transaction_id = [0u8; TRANSACTION_ID_LEN];
        transaction_id.copy_from_slice(&bytes[8..20]);

        let method_code = (message_type & 0x000F)
            | ((message_type & 0x00E0) >> 1)
            | ((message_type & 0x3E00) >> 2);
        let class_code = ((message_type >> 7) & 0x2) | ((message_type >> 4) & 0x1);

        let method = match method_code {
            METHOD_BINDING => Method::Binding,
            other => {
                return Err(Error::Stun(format!("不支持的方法 {other:#06x}")));
            }
        };

        // 只解析前 `length` 字节，多余的尾巴（比如 UDP 缓冲区里的填充）忽略。
        let body = &bytes[HEADER_LEN..HEADER_LEN + length];
        let attributes = decode_attributes(body, &transaction_id)?;

        Ok(Self {
            method,
            class: MessageClass::from_code(class_code),
            transaction_id,
            attributes,
        })
    }
}

/// IEEE CRC-32（反射，多项式 0xEDB88320），和 zlib 用的是同一个。
///
/// 不引依赖，按位算。STUN 报文很小，性能无所谓。
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            // mask = 最低位为 1 时全 1，否则全 0（避免分支）。
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// 校验 FINGERPRINT。
///
/// 报文没带指纹就跳过——不是所有服务器都回。带了就必须对，且必须是最后一个属性。
fn verify_fingerprint(bytes: &[u8], body_len: usize) -> Result<()> {
    let end = HEADER_LEN + body_len;
    let mut cursor = HEADER_LEN;

    while cursor + 4 <= end {
        let kind = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        let len = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize;
        let padded = len + ((4 - (len % 4)) % 4);

        if kind == ATTR_FINGERPRINT {
            if len != 4 {
                return Err(Error::Stun(format!("FINGERPRINT 长度应为 4，实际 {len}")));
            }
            if cursor + FINGERPRINT_LEN != end {
                return Err(Error::Stun("FINGERPRINT 必须是最后一个属性".into()));
            }
            let value = u32::from_be_bytes([
                bytes[cursor + 4],
                bytes[cursor + 5],
                bytes[cursor + 6],
                bytes[cursor + 7],
            ]);
            let expected = crc32(&bytes[..cursor]) ^ FINGERPRINT_XOR;
            if value != expected {
                return Err(Error::Stun(format!(
                    "FINGERPRINT 校验失败：报文声称 {value:#010x}，实算 {expected:#010x}"
                )));
            }
            return Ok(());
        }

        cursor += 4 + padded;
    }

    Ok(())
}

fn encode_attribute(
    out: &mut Vec<u8>,
    attribute: &Attribute,
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) {
    match attribute {
        Attribute::MappedAddress(addr) => {
            encode_address_attribute(out, ATTR_MAPPED_ADDRESS, *addr, false, transaction_id)
        }
        Attribute::XorMappedAddress(addr) => {
            encode_address_attribute(out, ATTR_XOR_MAPPED_ADDRESS, *addr, true, transaction_id)
        }
        Attribute::ResponseOrigin(addr) => {
            encode_address_attribute(out, ATTR_RESPONSE_ORIGIN, *addr, false, transaction_id)
        }
        Attribute::OtherAddress(addr) => {
            encode_address_attribute(out, ATTR_OTHER_ADDRESS, *addr, false, transaction_id)
        }
        Attribute::Software(text) => {
            let value = text.as_bytes();
            out.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
            push_padding(out, value.len());
        }
        Attribute::Unknown { kind, value } => {
            // FINGERPRINT 由编码器统一生成，这里手工塞一个会破坏「必须是最后一个
            // 属性」的约束，所以直接忽略。
            if *kind == ATTR_FINGERPRINT {
                return;
            }
            out.extend_from_slice(&kind.to_be_bytes());
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
            push_padding(out, value.len());
        }
    }
}

/// 地址类属性：`[1 字节保留][1 字节族][2 字节端口][地址]`。
///
/// XOR 形式（RFC 5389 §15.2）：IPv4 的地址与 magic cookie 异或、端口与
/// cookie 高 16 位异或；IPv6 的地址与 `cookie || transaction id` 异或。
/// IPv6 那条依赖事务 ID，所以编码时必须把消息的事务 ID 传进来，否则
/// 编出来的字节自己都解不回去。
fn encode_address_attribute(
    out: &mut Vec<u8>,
    kind: u16,
    addr: SocketAddr,
    xor: bool,
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) {
    let mut value = Vec::with_capacity(20);
    value.push(0); // 保留字节

    let (family, raw) = match addr.ip() {
        IpAddr::V4(v4) => (FAMILY_IPV4, v4.octets().to_vec()),
        IpAddr::V6(v6) => (FAMILY_IPV6, v6.octets().to_vec()),
    };

    // XOR 掩码：IPv4 只用 magic cookie，IPv6 用 cookie || transaction id。
    let mut mask = MAGIC_COOKIE.to_be_bytes().to_vec();
    match addr.ip() {
        IpAddr::V4(_) => mask.extend_from_slice(&[0u8; TRANSACTION_ID_LEN]),
        IpAddr::V6(_) => mask.extend_from_slice(transaction_id),
    }

    value.push(family);

    let port = if xor {
        addr.port() ^ (MAGIC_COOKIE >> 16) as u16
    } else {
        addr.port()
    };
    value.extend_from_slice(&port.to_be_bytes());

    if xor {
        for (index, byte) in raw.iter().enumerate() {
            value.push(byte ^ mask[index]);
        }
    } else {
        value.extend_from_slice(&raw);
    }

    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(&value);
    push_padding(out, value.len());
}

fn push_padding(out: &mut Vec<u8>, len: usize) {
    let padding = (4 - (len % 4)) % 4;
    out.extend(std::iter::repeat_n(0u8, padding));
}

fn decode_attributes(
    body: &[u8],
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Result<Vec<Attribute>> {
    let mut attributes = Vec::new();
    let mut cursor = 0usize;

    while cursor < body.len() {
        if cursor + 4 > body.len() {
            return Err(Error::Stun("属性头被截断".into()));
        }
        let kind = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
        let len = u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]) as usize;
        cursor += 4;

        let padded = len + ((4 - (len % 4)) % 4);
        if cursor + padded > body.len() {
            return Err(Error::Stun(format!(
                "属性 {kind:#06x} 声称 {len} 字节，超出报文范围"
            )));
        }
        let value = &body[cursor..cursor + len];
        cursor += padded;

        // FINGERPRINT 已经在 verify_fingerprint 里校验过了，不进属性列表，
        // 这样 encode → decode 的属性集合保持一致。
        if kind == ATTR_FINGERPRINT {
            continue;
        }

        attributes.push(decode_attribute(kind, value, transaction_id)?);
    }

    Ok(attributes)
}

fn decode_attribute(
    kind: u16,
    value: &[u8],
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Result<Attribute> {
    match kind {
        ATTR_MAPPED_ADDRESS
        | ATTR_XOR_MAPPED_ADDRESS
        | ATTR_RESPONSE_ORIGIN
        | ATTR_OTHER_ADDRESS => {
            let xor = kind == ATTR_XOR_MAPPED_ADDRESS;
            let addr = decode_address(value, xor, transaction_id)?;
            Ok(match kind {
                ATTR_MAPPED_ADDRESS => Attribute::MappedAddress(addr),
                ATTR_XOR_MAPPED_ADDRESS => Attribute::XorMappedAddress(addr),
                ATTR_RESPONSE_ORIGIN => Attribute::ResponseOrigin(addr),
                _ => Attribute::OtherAddress(addr),
            })
        }
        ATTR_SOFTWARE => Ok(Attribute::Software(
            String::from_utf8_lossy(value).into_owned(),
        )),
        _ => Ok(Attribute::Unknown {
            kind,
            value: value.to_vec(),
        }),
    }
}

fn decode_address(
    value: &[u8],
    xor: bool,
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Result<SocketAddr> {
    if value.len() < 4 {
        return Err(Error::Stun("地址属性短于 4 字节".into()));
    }
    let family = value[1];
    let raw_port = u16::from_be_bytes([value[2], value[3]]);
    let port = if xor {
        raw_port ^ (MAGIC_COOKIE >> 16) as u16
    } else {
        raw_port
    };

    let body = &value[4..];
    let ip = match family {
        FAMILY_IPV4 => {
            if body.len() < 4 {
                return Err(Error::Stun("IPv4 地址不足 4 字节".into()));
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&body[..4]);
            if xor {
                let mask = MAGIC_COOKIE.to_be_bytes();
                for (index, octet) in octets.iter_mut().enumerate() {
                    *octet ^= mask[index];
                }
            }
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        FAMILY_IPV6 => {
            if body.len() < 16 {
                return Err(Error::Stun("IPv6 地址不足 16 字节".into()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&body[..16]);
            if xor {
                let mut mask = MAGIC_COOKIE.to_be_bytes().to_vec();
                mask.extend_from_slice(transaction_id);
                for (index, octet) in octets.iter_mut().enumerate() {
                    *octet ^= mask[index];
                }
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        other => {
            return Err(Error::Stun(format!("未知地址族 {other}")));
        }
    };

    Ok(SocketAddr::new(ip, port))
}

/// 一次 STUN 查询的结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StunResult {
    /// NAT 外侧看到的地址，也就是「本机在公网上的样子」。
    pub mapped_addr: SocketAddr,
    /// 服务器回包的源地址。
    pub response_origin: Option<SocketAddr>,
    /// CHANGE-REQUEST 用的备用地址，做 NAT 行为判定时需要。
    pub other_address: Option<SocketAddr>,
    pub software: Option<String>,
}

/// 用**指定的** socket 向 `server` 发一次 Binding 请求。
///
/// 复用同一个 socket 很关键：映射是按「本地端口」分配的，换个 socket
/// 问出来的就是另一个映射，用来做打洞就错了。
pub async fn query_binding_with(
    socket: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Result<StunResult> {
    let transaction_id: [u8; TRANSACTION_ID_LEN] = rand::random();
    let request = Message::binding_request(transaction_id).encode();

    socket.send_to(&request, server).await?;

    let mut buffer = vec![0u8; 1500];
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(Error::Stun(format!("等待 {server} 的响应超时")));
        }

        let (len, from) = match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await
        {
            Ok(result) => result?,
            Err(_) => return Err(Error::Stun(format!("等待 {server} 的响应超时"))),
        };

        // 同一个 socket 上可能混进别的包（比如对端发来的打洞探测），按事务 ID 过滤。
        let message = match Message::decode(&buffer[..len]) {
            Ok(message) => message,
            Err(_) => continue,
        };
        if message.transaction_id != transaction_id {
            continue;
        }
        if message.class == MessageClass::ErrorResponse {
            return Err(Error::Stun(format!("{from} 返回了错误响应")));
        }

        let mapped_addr = message
            .mapped_address()
            .ok_or_else(|| Error::Stun("响应里没有映射地址属性".into()))?;

        return Ok(StunResult {
            mapped_addr,
            response_origin: message.response_origin().or(Some(from)),
            other_address: message.other_address(),
            software: message.software().map(str::to_string),
        });
    }
}

/// 自己开一个临时 socket 做一次 STUN 查询。
///
/// 只适合「看一眼我的公网地址」这种场景；真打洞要用 [`query_binding_with`]
/// 复用固定的本地端口。
pub async fn query_binding(server: SocketAddr, timeout: Duration) -> Result<StunResult> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind).await?;
    query_binding_with(&socket, server, timeout).await
}

/// 解析 `host:port` 形式的 STUN 服务器地址。
pub async fn resolve_server(spec: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(spec)
        .await
        .map_err(|err| Error::Stun(format!("无法解析 STUN 服务器 {spec}: {err}")))?
        .next()
        .ok_or_else(|| Error::Stun(format!("STUN 服务器 {spec} 没有解析出任何地址")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(message: &Message) -> Message {
        Message::decode(&message.encode()).expect("解码应当成功")
    }

    #[test]
    fn 消息类型位交错符合_rfc() {
        // Binding Request / Success / Error / Indication 的经典取值。
        let cases = [
            (MessageClass::Request, 0x0001u16),
            (MessageClass::SuccessResponse, 0x0101),
            (MessageClass::ErrorResponse, 0x0111),
            (MessageClass::Indication, 0x0011),
        ];
        for (class, expected) in cases {
            let message = Message {
                method: Method::Binding,
                class,
                transaction_id: [0u8; 12],
                attributes: vec![],
            };
            let encoded = message.encode();
            let actual = u16::from_be_bytes([encoded[0], encoded[1]]);
            assert_eq!(actual, expected, "{class:?} 编码错误");
            assert_eq!(roundtrip(&message).class, class, "{class:?} 解码错误");
        }
    }

    #[test]
    fn 请求头部字段正确() {
        let id = [0xAB; 12];
        let encoded = Message::binding_request(id).encode();

        // 只有自动附带的 FINGERPRINT。
        assert_eq!(encoded.len(), HEADER_LEN + FINGERPRINT_LEN);
        assert_eq!(&encoded[0..2], &[0x00, 0x01]);
        assert_eq!(
            u16::from_be_bytes([encoded[2], encoded[3]]) as usize,
            FINGERPRINT_LEN,
            "长度字段应只算 FINGERPRINT"
        );
        assert_eq!(&encoded[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&encoded[8..20], &id);

        // FINGERPRINT 必须是最后一个属性。
        let tail = &encoded[HEADER_LEN..];
        assert_eq!(u16::from_be_bytes([tail[0], tail[1]]), ATTR_FINGERPRINT);
        assert_eq!(u16::from_be_bytes([tail[2], tail[3]]), 4);
    }

    #[test]
    fn crc32_符合标准测试向量() {
        // CRC-32/ISO-HDLC 的经典校验值。
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
    }

    #[test]
    fn 指纹自洽且能检出篡改() {
        let message = Message {
            method: Method::Binding,
            class: MessageClass::SuccessResponse,
            transaction_id: [0x5A; 12],
            attributes: vec![Attribute::XorMappedAddress(
                "203.0.113.7:4000".parse().unwrap(),
            )],
        };
        let encoded = message.encode();

        // 原样解码应当成功。
        assert!(Message::decode(&encoded).is_ok());

        // 改动属性值里的一个字节（这里是保留字节），指纹就对不上了。
        let mut tampered = encoded.clone();
        let value_index = HEADER_LEN + 4;
        tampered[value_index] ^= 0x01;
        let err = Message::decode(&tampered).unwrap_err();
        assert!(
            matches!(&err, Error::Stun(text) if text.contains("FINGERPRINT")),
            "应报指纹错误，实际 {err:?}"
        );

        // 改事务 ID 同样会被指纹拦住。
        let mut tampered_id = encoded;
        tampered_id[9] ^= 0xff;
        assert!(Message::decode(&tampered_id).is_err());
    }

    #[test]
    fn 没有指纹的报文仍然接受() {
        // 手工拼一个不带 FINGERPRINT 的响应，模拟老服务器。
        let mut raw = Vec::new();
        raw.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Success
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        raw.extend_from_slice(&[0x11; 12]);

        let decoded = Message::decode(&raw).unwrap();
        assert_eq!(decoded.class, MessageClass::SuccessResponse);
    }

    #[test]
    fn 指纹不在最后会被拒绝() {
        // 构造：SOFTWARE 属性 + 指纹 + 尾巴属性 → 指纹位置非法。
        let message = Message {
            method: Method::Binding,
            class: MessageClass::SuccessResponse,
            transaction_id: [0x66; 12],
            attributes: vec![Attribute::Software("x".into())],
        };
        let mut encoded = message.encode();

        // 在指纹后面再挂一个属性，并把长度字段改对。
        encoded.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
        encoded.extend_from_slice(&4u16.to_be_bytes());
        encoded.extend_from_slice(&[0u8; 4]);
        let new_len = (encoded.len() - HEADER_LEN) as u16;
        encoded[2..4].copy_from_slice(&new_len.to_be_bytes());

        let err = Message::decode(&encoded).unwrap_err();
        assert!(
            matches!(&err, Error::Stun(text) if text.contains("最后一个属性")),
            "实际 {err:?}"
        );
    }

    #[test]
    fn ipv4_异或映射地址往返() {
        let addr: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let message = Message {
            method: Method::Binding,
            class: MessageClass::SuccessResponse,
            transaction_id: [0x11; 12],
            attributes: vec![Attribute::XorMappedAddress(addr)],
        };
        assert_eq!(roundtrip(&message).mapped_address(), Some(addr));
    }

    #[test]
    fn ipv6_异或映射地址往返() {
        let addr: SocketAddr = "[2001:db8::1234:5678]:9999".parse().unwrap();
        let message = Message {
            method: Method::Binding,
            class: MessageClass::SuccessResponse,
            transaction_id: [0x22; 12],
            attributes: vec![Attribute::XorMappedAddress(addr)],
        };
        assert_eq!(roundtrip(&message).mapped_address(), Some(addr));
    }

    #[test]
    fn ipv4_xor_编码与_rfc_示例一致() {
        // 手算校验：端口 32853 ^ (0x2112A442 >> 16 = 0x2112)
        let addr: SocketAddr = "192.0.2.1:32853".parse().unwrap();
        let mut out = Vec::new();
        encode_address_attribute(&mut out, ATTR_XOR_MAPPED_ADDRESS, addr, true, &[0u8; 12]);

        assert_eq!(
            u16::from_be_bytes([out[0], out[1]]),
            ATTR_XOR_MAPPED_ADDRESS
        );
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 8);
        assert_eq!(out[4], 0, "保留字节");
        assert_eq!(out[5], FAMILY_IPV4);

        let expected_port = 32853u16 ^ 0x2112u16;
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), expected_port);

        let cookie = MAGIC_COOKIE.to_be_bytes();
        for (index, byte) in [192u8, 0, 2, 1].iter().enumerate() {
            assert_eq!(out[8 + index], byte ^ cookie[index]);
        }
        // 整个属性长度必须是 4 的倍数
        assert_eq!(out.len() % 4, 0);
    }

    #[test]
    fn 非异或映射地址往返() {
        let addr: SocketAddr = "198.51.100.20:1234".parse().unwrap();
        let message = Message {
            method: Method::Binding,
            class: MessageClass::SuccessResponse,
            transaction_id: [0x33; 12],
            attributes: vec![Attribute::MappedAddress(addr)],
        };
        assert_eq!(roundtrip(&message).mapped_address(), Some(addr));
    }

    #[test]
    fn 各种属性一起往返() {
        let message = Message {
            method: Method::Binding,
            class: MessageClass::SuccessResponse,
            transaction_id: [0x44; 12],
            attributes: vec![
                Attribute::XorMappedAddress("203.0.113.9:60000".parse().unwrap()),
                Attribute::ResponseOrigin("203.0.113.1:3478".parse().unwrap()),
                Attribute::OtherAddress("203.0.113.2:3479".parse().unwrap()),
                Attribute::Software("p2p_file/0.1".into()),
                Attribute::Unknown {
                    kind: 0x9999,
                    value: vec![1, 2, 3, 4, 5],
                },
            ],
        };
        let decoded = roundtrip(&message);
        assert_eq!(decoded.attributes, message.attributes);
        assert_eq!(decoded.response_origin().unwrap().port(), 3478);
        assert_eq!(decoded.other_address().unwrap().port(), 3479);
        assert_eq!(decoded.software(), Some("p2p_file/0.1"));
    }

    #[test]
    fn 软件名长度非四倍数时正确补齐() {
        // "abcde" 长 5，应补 3 字节
        let message = Message {
            method: Method::Binding,
            class: MessageClass::SuccessResponse,
            transaction_id: [0x55; 12],
            attributes: vec![
                Attribute::Software("abcde".into()),
                Attribute::XorMappedAddress("203.0.113.9:60000".parse().unwrap()),
            ],
        };
        let encoded = message.encode();
        assert_eq!((encoded.len() - HEADER_LEN) % 4, 0);
        assert_eq!(roundtrip(&message).attributes, message.attributes);
    }

    #[test]
    fn 报文过短报错() {
        assert!(Message::decode(&[0u8; 4]).is_err());
        assert!(Message::decode(&[]).is_err());
    }

    #[test]
    fn cookie_不对报错() {
        let mut encoded = Message::binding_request([0u8; 12]).encode();
        encoded[4] ^= 0xff;
        assert!(Message::decode(&encoded).is_err());
    }

    #[test]
    fn 长度字段越界报错() {
        let mut encoded = Message::binding_request([0u8; 12]).encode();
        encoded[2] = 0xff;
        encoded[3] = 0xfc; // 声称 65532 字节属性
        assert!(Message::decode(&encoded).is_err());
    }

    #[test]
    fn 长度字段非四倍数报错() {
        let mut encoded = Message::binding_request([0u8; 12]).encode();
        encoded[3] = 0x03;
        assert!(Message::decode(&encoded).is_err());
    }

    #[test]
    fn 属性头被截断报错() {
        let mut encoded = Message::binding_request([0u8; 12]).encode();
        encoded[2] = 0x00;
        encoded[3] = 0x02; // 声称 2 字节属性，不足以放一个 TLV 头
        encoded.extend_from_slice(&[0x00, 0x00]);
        assert!(Message::decode(&encoded).is_err());
    }

    #[test]
    fn 未知方法报错() {
        let mut encoded = Message::binding_request([0u8; 12]).encode();
        // 把方法字段改成 0x0002
        encoded[1] = 0x02;
        assert!(Message::decode(&encoded).is_err());
    }

    #[test]
    fn 事务_id_不匹配时过滤() {
        let mut a = Message::binding_request([1u8; 12]);
        a.attributes
            .push(Attribute::XorMappedAddress("1.2.3.4:5".parse().unwrap()));
        let decoded = Message::decode(&a.encode()).unwrap();
        assert_ne!(decoded.transaction_id, [2u8; 12]);
        assert_eq!(decoded.transaction_id, [1u8; 12]);
    }

    #[tokio::test]
    async fn 本地_udp_上跑通一次查询() {
        // 起一个玩具「STUN 服务器」，直接回一个 XOR-MAPPED-ADDRESS。
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

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

        let result = query_binding(server_addr, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(result.mapped_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(result.response_origin, Some(server_addr));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn 无响应时超时() {
        // 127.0.0.1 上一个没人监听的端口：可能收到 ICMP 端口不可达（Io 错误），
        // 也可能石沉大海（超时）。两种都算「查不到」，但绝不能返回一个假地址。
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let err = query_binding(dead_addr, Duration::from_millis(300))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Stun(_) | Error::Io(_)), "实际 {err:?}");
    }

    #[tokio::test]
    async fn 解析服务器地址() {
        let addr = resolve_server("127.0.0.1:3478").await.unwrap();
        assert_eq!(addr.port(), 3478);
        // 语法非法的地址应立刻报错，不该去做 DNS 查询。
        assert!(resolve_server("256.256.256.256:1").await.is_err());
    }
}
