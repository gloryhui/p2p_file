//! 应用层握手：把「对面是谁」这件事钉死。
//!
//! QUIC 已经把通道加密了，但加密不等于知道对面是谁——因为证书是自签的。
//! 握手的作用就是补上身份这一环：
//!
//! ```text
//! 发起方                                接收方
//!   Hello { id, pubkey, nonce_a }  ──────►
//!                                  ◄────── HelloAck { id, pubkey, nonce_b, sig_b }
//!   Auth { sig_a }                 ──────►
//!                                  ◄────── Ready
//! ```
//!
//! - `sig` 是对 [`handshake_payload`] 的签名，载荷包含**双方**公钥和**双方**
//!   随机数，所以签名既绑定了身份，也绑定了这一次会话（防重放）。
//! - 收到的公钥必须能推导出对方声称的节点 ID，否则是冒名。
//! - 双方都签名，因此是双向认证：不光发起方确认接收方，接收方也确认发起方。
//!
//! 只要跑完这个握手，后面传输的数据就可以确信是发给自己想发给的那个节点的。

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::identity::{
    Identity, NodeId, public_key_from_bytes, signature_from_bytes, verify_signature,
};
use crate::protocol::frame::{read_frame, write_frame};
use crate::protocol::message::{ControlMessage, PROTOCOL_VERSION, handshake_payload};

/// 握手成功后拿到的对端信息。
#[derive(Clone, Debug)]
pub struct HandshakeOutcome {
    /// 对端节点 ID（由对端公钥推导，已核对过）。
    pub peer_node_id: NodeId,
    /// 对端公钥。
    pub peer_public_key: ed25519_dalek::VerifyingKey,
}

/// 发起方握手。
pub async fn handshake_initiator<S, R>(
    send: &mut S,
    recv: &mut R,
    identity: &Identity,
) -> Result<HandshakeOutcome>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let nonce: [u8; 32] = rand::random();

    write_frame(
        send,
        &ControlMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            node_id: identity.node_id(),
            public_key: identity.public_key_bytes(),
            nonce,
        },
    )
    .await?;

    let reply = read_frame(recv)
        .await?
        .ok_or_else(|| Error::Protocol("对端在 Hello 之后没回应就关闭了连接".into()))?;

    let (peer_nonce, peer_public_key, peer_node_id, signature) = match reply {
        ControlMessage::HelloAck {
            protocol_version,
            node_id,
            public_key,
            nonce: peer_nonce,
            peer_nonce: echoed,
            signature,
        } => {
            check_version(protocol_version)?;
            if echoed != nonce {
                return Err(Error::Protocol(
                    "HelloAck 回显的随机数与发出的不符，可能是重放的应答".into(),
                ));
            }
            let key = public_key_from_bytes(&public_key)?;
            check_node_id(&key, node_id)?;
            (peer_nonce, key, node_id, signature)
        }
        ControlMessage::Abort { reason } => {
            return Err(Error::Protocol(format!("对端拒绝握手: {reason}")));
        }
        other => {
            return Err(Error::Protocol(format!(
                "握手阶段收到意外消息 {}",
                other.kind()
            )));
        }
    };

    let payload = handshake_payload(
        &identity.public_key_bytes(),
        &nonce,
        &peer_public_key.to_bytes(),
        &peer_nonce,
    );
    verify_signature(
        &peer_public_key,
        &payload,
        &signature_from_bytes(&signature)?,
    )?;

    // 回签，让对端也确认我们的身份。
    let our_signature = identity.sign(&payload);
    write_frame(
        send,
        &ControlMessage::Auth {
            signature: our_signature.to_bytes().to_vec(),
        },
    )
    .await?;

    expect_ready(recv).await?;

    Ok(HandshakeOutcome {
        peer_node_id,
        peer_public_key,
    })
}

/// 接收方握手。
pub async fn handshake_responder<S, R>(
    send: &mut S,
    recv: &mut R,
    identity: &Identity,
) -> Result<HandshakeOutcome>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let hello = read_frame(recv)
        .await?
        .ok_or_else(|| Error::Protocol("对端在发 Hello 之前就关闭了连接".into()))?;

    let (peer_nonce, peer_public_key, peer_node_id) = match hello {
        ControlMessage::Hello {
            protocol_version,
            node_id,
            public_key,
            nonce,
        } => {
            check_version(protocol_version)?;
            let key = public_key_from_bytes(&public_key)?;
            // 关键一步：公钥必须能推出对方声称的节点 ID。
            check_node_id(&key, node_id)?;
            (nonce, key, node_id)
        }
        other => {
            return Err(Error::Protocol(format!(
                "握手阶段期待 Hello，收到 {}",
                other.kind()
            )));
        }
    };

    let our_nonce: [u8; 32] = rand::random();
    let payload = handshake_payload(
        &peer_public_key.to_bytes(),
        &peer_nonce,
        &identity.public_key_bytes(),
        &our_nonce,
    );

    let our_signature = identity.sign(&payload);
    write_frame(
        send,
        &ControlMessage::HelloAck {
            protocol_version: PROTOCOL_VERSION,
            node_id: identity.node_id(),
            public_key: identity.public_key_bytes(),
            nonce: our_nonce,
            peer_nonce,
            signature: our_signature.to_bytes().to_vec(),
        },
    )
    .await?;

    let auth = read_frame(recv)
        .await?
        .ok_or_else(|| Error::Protocol("对端没有回签就关闭了连接".into()))?;

    match auth {
        ControlMessage::Auth { signature } => {
            verify_signature(
                &peer_public_key,
                &payload,
                &signature_from_bytes(&signature)?,
            )?;
        }
        other => {
            return Err(Error::Protocol(format!(
                "握手阶段期待 Auth，收到 {}",
                other.kind()
            )));
        }
    }

    write_frame(send, &ControlMessage::Ready).await?;

    Ok(HandshakeOutcome {
        peer_node_id,
        peer_public_key,
    })
}

fn check_version(version: u32) -> Result<()> {
    if version != PROTOCOL_VERSION {
        return Err(Error::Protocol(format!(
            "协议版本不兼容：本机 {PROTOCOL_VERSION}，对端 {version}"
        )));
    }
    Ok(())
}

fn check_node_id(public_key: &ed25519_dalek::VerifyingKey, claimed: NodeId) -> Result<()> {
    let derived = NodeId::from_public_key(public_key);
    if derived != claimed {
        return Err(Error::Protocol(format!(
            "节点 ID 与公钥不符：声称 {}，公钥实为 {}",
            claimed.short(),
            derived.short()
        )));
    }
    Ok(())
}

async fn expect_ready<R>(recv: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let message = read_frame(recv)
        .await?
        .ok_or_else(|| Error::Protocol("等待 Ready 时连接被关闭".into()))?;

    match message {
        ControlMessage::Ready => Ok(()),
        ControlMessage::Abort { reason } => Err(Error::Protocol(format!("对端中止: {reason}"))),
        other => Err(Error::Protocol(format!(
            "期待 Ready，收到 {}",
            other.kind()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一条双向通道的一半：读端 + 写端。
    type Half = (
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
    );

    /// 把一条双向通道切成读写两半，方便并发跑握手两侧。
    fn split_pair() -> (Half, Half) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (tokio::io::split(a), tokio::io::split(b))
    }

    #[tokio::test]
    async fn 双向握手成功并互相确认身份() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let ((mut a_recv, mut a_send), (mut b_recv, mut b_send)) = split_pair();

        let (alice_result, bob_result) = tokio::join!(
            handshake_initiator(&mut a_send, &mut a_recv, &alice),
            handshake_responder(&mut b_send, &mut b_recv, &bob),
        );

        let alice_outcome = alice_result.unwrap();
        let bob_outcome = bob_result.unwrap();

        assert_eq!(alice_outcome.peer_node_id, bob.node_id());
        assert_eq!(bob_outcome.peer_node_id, alice.node_id());
        assert_eq!(alice_outcome.peer_public_key, bob.public_key());
        assert_eq!(bob_outcome.peer_public_key, alice.public_key());
    }

    #[tokio::test]
    async fn 冒用他人节点_id_会被拒绝() {
        let alice = Identity::generate();
        let mallory = Identity::generate();
        let ((mut m_recv, mut m_send), (mut b_recv, mut b_send)) = split_pair();

        let responder = tokio::spawn(async move {
            let bob = Identity::generate();
            handshake_responder(&mut b_send, &mut b_recv, &bob).await
        });

        // Mallory 声称自己是 Alice，但只能拿出自己的公钥。
        write_frame(
            &mut m_send,
            &ControlMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
                node_id: alice.node_id(),
                public_key: mallory.public_key_bytes(),
                nonce: [1u8; 32],
            },
        )
        .await
        .unwrap();

        let result = responder.await.unwrap();
        assert!(result.is_err(), "公钥推不出声称的节点 ID，必须拒绝");
        // 顺手确认 Mallory 那边也等不到正常回应。
        let _ = read_frame(&mut m_recv).await;
    }

    #[tokio::test]
    async fn 签名不对会被拒绝() {
        let mallory = Identity::generate();
        let third_party = Identity::generate();
        let bob = Identity::generate();
        let bob_public_key = bob.public_key();

        let ((mut m_recv, mut m_send), (mut b_recv, mut b_send)) = split_pair();

        let responder =
            tokio::spawn(async move { handshake_responder(&mut b_send, &mut b_recv, &bob).await });

        // 这次节点 ID 和公钥是自洽的，Mallory 身份合法，但回签想用别人的密钥。
        let mallory_nonce = [2u8; 32];
        write_frame(
            &mut m_send,
            &ControlMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
                node_id: mallory.node_id(),
                public_key: mallory.public_key_bytes(),
                nonce: mallory_nonce,
            },
        )
        .await
        .unwrap();

        let ack = read_frame(&mut m_recv).await.unwrap().unwrap();
        let bob_nonce = match ack {
            ControlMessage::HelloAck {
                nonce, peer_nonce, ..
            } => {
                assert_eq!(peer_nonce, mallory_nonce, "应回显我方随机数");
                nonce
            }
            other => panic!("期待 HelloAck，收到 {}", other.kind()),
        };

        // 按和实现相同的规则重建签名载荷，然后**用错误的密钥**签名。
        let payload = handshake_payload(
            &mallory.public_key_bytes(),
            &mallory_nonce,
            &bob_public_key.to_bytes(),
            &bob_nonce,
        );
        let bad_signature = third_party.sign(&payload);

        write_frame(
            &mut m_send,
            &ControlMessage::Auth {
                signature: bad_signature.to_bytes().to_vec(),
            },
        )
        .await
        .unwrap();

        assert!(responder.await.unwrap().is_err(), "签名验不过必须拒绝");
    }

    #[tokio::test]
    async fn 协议版本不匹配会被拒绝() {
        let mallory = Identity::generate();
        let ((_m_recv, mut m_send), (mut b_recv, mut b_send)) = split_pair();

        let responder = tokio::spawn(async move {
            let bob = Identity::generate();
            handshake_responder(&mut b_send, &mut b_recv, &bob).await
        });

        write_frame(
            &mut m_send,
            &ControlMessage::Hello {
                protocol_version: PROTOCOL_VERSION + 1,
                node_id: mallory.node_id(),
                public_key: mallory.public_key_bytes(),
                nonce: [3u8; 32],
            },
        )
        .await
        .unwrap();

        assert!(responder.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn 期待_hello_却收到别的消息会报错() {
        let ((_m_recv, mut m_send), (mut b_recv, mut b_send)) = split_pair();

        let responder = tokio::spawn(async move {
            let bob = Identity::generate();
            handshake_responder(&mut b_send, &mut b_recv, &bob).await
        });

        write_frame(&mut m_send, &ControlMessage::Ready)
            .await
            .unwrap();
        assert!(responder.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn 对端提前断开时报错而不是挂死() {
        let ((m_recv, m_send), (mut b_recv, mut b_send)) = split_pair();
        // 直接丢掉发起方这一半，模拟对端跑路。
        drop(m_recv);
        drop(m_send);

        let bob = Identity::generate();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handshake_responder(&mut b_send, &mut b_recv, &bob),
        )
        .await
        .expect("不该挂死");

        assert!(result.is_err());
    }
}
