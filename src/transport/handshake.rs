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
//! - `sig` 是对 [`handshake_payload`] 的签名，载荷包含**双方**公钥、**双方**
//!   随机数，以及**当前 QUIC/TLS 会话**导出的 channel binding，所以签名既绑定了
//!   身份，也绑定了这一次会话。
//! - 收到的公钥必须能推导出对方声称的节点 ID，否则是冒名。
//! - 双方都签名，因此是双向认证：不光发起方确认接收方，接收方也确认发起方。
//!
//! 会话绑定值（[`ChannelBinding`]）是防透明 MITM 的关键：它让「把一条连接上的
//! 握手消息原样搬到另一条连接」必然失败。签名里必须带**当前连接**导出的值，
//! 不能是常量、空值或调用方自己生成的随机数——调用方只能从 [`quinn::Connection`]
//! 导出，见 [`ChannelBinding::from_connection`]。
//!
//! 只要跑完这个握手，后面传输的数据就可以确信是发给自己想发给的那个节点的。

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::identity::{
    Identity, NodeId, public_key_from_bytes, signature_from_bytes, verify_signature,
};
use crate::protocol::frame::{read_frame, write_frame};
use crate::protocol::message::{ControlMessage, PROTOCOL_VERSION, handshake_payload};
use crate::transport::quic::ChannelBinding;

/// 握手成功后拿到的对端信息。
#[derive(Clone, Debug)]
pub struct HandshakeOutcome {
    /// 对端节点 ID（由对端公钥推导，已核对过）。
    pub peer_node_id: NodeId,
    /// 对端公钥。
    pub peer_public_key: ed25519_dalek::VerifyingKey,
}

/// 发起方握手。
///
/// `binding` 必须是**当前** `quinn::Connection` 导出的会话绑定值；它会被写进
/// 签名载荷，从而把这次认证钉死在这条 TLS 会话上。
pub async fn handshake_initiator<S, R>(
    send: &mut S,
    recv: &mut R,
    identity: &Identity,
    binding: &ChannelBinding,
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
        binding.as_bytes(),
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
///
/// `binding` 同 [`handshake_initiator`]，必须是当前连接的会话绑定值。
pub async fn handshake_responder<S, R>(
    send: &mut S,
    recv: &mut R,
    identity: &Identity,
    binding: &ChannelBinding,
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
        binding.as_bytes(),
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

    /// 测试用的固定会话绑定值。
    fn test_binding() -> ChannelBinding {
        ChannelBinding::from_bytes_for_test([0x5a; 32])
    }

    #[tokio::test]
    async fn 双向握手成功并互相确认身份() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let binding = test_binding();
        let ((mut a_recv, mut a_send), (mut b_recv, mut b_send)) = split_pair();

        let (alice_result, bob_result) = tokio::join!(
            handshake_initiator(&mut a_send, &mut a_recv, &alice, &binding),
            handshake_responder(&mut b_send, &mut b_recv, &bob, &binding),
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
        let binding = test_binding();
        let ((mut m_recv, mut m_send), (mut b_recv, mut b_send)) = split_pair();

        let responder = tokio::spawn(async move {
            let bob = Identity::generate();
            handshake_responder(&mut b_send, &mut b_recv, &bob, &binding).await
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
        let binding = test_binding();

        let ((mut m_recv, mut m_send), (mut b_recv, mut b_send)) = split_pair();

        let responder = tokio::spawn(async move {
            handshake_responder(&mut b_send, &mut b_recv, &bob, &binding).await
        });

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
            binding.as_bytes(),
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
        let binding = test_binding();
        let ((_m_recv, mut m_send), (mut b_recv, mut b_send)) = split_pair();

        let responder = tokio::spawn(async move {
            let bob = Identity::generate();
            handshake_responder(&mut b_send, &mut b_recv, &bob, &binding).await
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

    /// v2 把会话绑定值纳入签名载荷，与 v1 不兼容。
    ///
    /// 旧节点必须收到**明确的版本错误**，而不是一路走到签名校验再报一个
    /// 看不出原因的「签名校验失败」。
    #[tokio::test]
    async fn 旧协议版本_v1_会被明确拒绝() {
        let mallory = Identity::generate();
        let binding = test_binding();
        let ((_m_recv, mut m_send), (mut b_recv, mut b_send)) = split_pair();

        let responder = tokio::spawn(async move {
            let bob = Identity::generate();
            handshake_responder(&mut b_send, &mut b_recv, &bob, &binding).await
        });

        write_frame(
            &mut m_send,
            &ControlMessage::Hello {
                protocol_version: 1,
                node_id: mallory.node_id(),
                public_key: mallory.public_key_bytes(),
                nonce: [4u8; 32],
            },
        )
        .await
        .unwrap();

        let error = responder.await.unwrap().expect_err("v1 必须被拒绝");
        let message = error.to_string();
        assert!(
            message.contains("协议版本不兼容"),
            "必须是明确的版本错误，实际: {message}"
        );
    }

    #[tokio::test]
    async fn 期待_hello_却收到别的消息会报错() {
        let binding = test_binding();
        let ((_m_recv, mut m_send), (mut b_recv, mut b_send)) = split_pair();

        let responder = tokio::spawn(async move {
            let bob = Identity::generate();
            handshake_responder(&mut b_send, &mut b_recv, &bob, &binding).await
        });

        write_frame(&mut m_send, &ControlMessage::Ready)
            .await
            .unwrap();
        assert!(responder.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn 对端提前断开时报错而不是挂死() {
        let binding = test_binding();
        let ((m_recv, m_send), (mut b_recv, mut b_send)) = split_pair();
        // 直接丢掉发起方这一半，模拟对端跑路。
        drop(m_recv);
        drop(m_send);

        let bob = Identity::generate();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handshake_responder(&mut b_send, &mut b_recv, &bob, &binding),
        )
        .await
        .expect("不该挂死");

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn 会话绑定值翻转一位后握手失败() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let mut flipped = *test_binding().as_bytes();
        flipped[13] ^= 0x01;
        assert_ne!(
            test_binding().as_bytes(),
            &flipped,
            "翻转 1 bit 后绑定值必须不同"
        );

        let alice_binding = test_binding();
        let bob_binding = ChannelBinding::from_bytes_for_test(flipped);

        let ((mut a_recv, mut a_send), (mut b_recv, mut b_send)) = split_pair();

        // 各自 spawn 成独立任务：一侧验签失败后会关掉自己那半边流，
        // 另一侧才能读到 EOF 而不是永远挂着等 Auth。
        let initiator = tokio::spawn(async move {
            handshake_initiator(&mut a_send, &mut a_recv, &alice, &alice_binding).await
        });
        let responder = tokio::spawn(async move {
            handshake_responder(&mut b_send, &mut b_recv, &bob, &bob_binding).await
        });

        let (alice_result, bob_result) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                (initiator.await.unwrap(), responder.await.unwrap())
            })
            .await
            .expect("绑定值不同时不该挂死");

        // 双方签名都自洽，但签名覆盖的绑定值不同，所以互相验不过。
        assert!(
            matches!(alice_result, Err(Error::Identity(_))),
            "绑定值不同时发起方必须因签名校验失败而拒绝，实际 {alice_result:?}"
        );
        assert!(bob_result.is_err(), "绑定值不同时接收方也不该完成认证");
    }

    /// 中间人建两条独立连接（A↔M、M↔B），把握手字节原样搬运。
    ///
    /// 这是本 issue 要修的旧 Bug 的复现路径：旧签名载荷只有「双方公钥 + 随机数」，
    /// 这种搬运能让 A、B 双方都验证通过。加入会话绑定后必须失败。
    #[tokio::test]
    async fn 跨会话原样转发握手消息无法通过认证() {
        run_relay_handshake([0x11; 32], [0x22; 32], false).await;
    }

    /// 对照组：绑定值相同（本来就在同一条会话里）时，转发器能把两端接起来。
    /// 用来证明上面的失败是绑定值不同造成的，而不是转发线路本身写错了。
    #[tokio::test]
    async fn 同一会话内转发握手消息可以完成认证() {
        run_relay_handshake([0x33; 32], [0x33; 32], true).await;
    }

    /// 让一个透明转发器把发起方与接收方的字节对接起来，返回两侧的握手结果。
    async fn run_relay_handshake(
        initiator_binding: [u8; 32],
        responder_binding: [u8; 32],
        expect_success: bool,
    ) {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            relay_handshake(initiator_binding, responder_binding, expect_success),
        )
        .await
        .expect("转发握手不该挂死");
    }

    async fn relay_handshake(
        initiator_binding: [u8; 32],
        responder_binding: [u8; 32],
        expect_success: bool,
    ) {
        use tokio::io::AsyncWriteExt;

        let alice = Identity::generate();
        let bob = Identity::generate();

        // A ↔ M 一条会话，M ↔ B 另一条会话。转发器对字节不做任何加工。
        let ((mut a_recv, mut a_send), (m_a_recv, m_a_send)) = split_pair();
        let ((m_b_recv, m_b_send), (mut b_recv, mut b_send)) = split_pair();

        let initiator_binding = ChannelBinding::from_bytes_for_test(initiator_binding);
        let responder_binding = ChannelBinding::from_bytes_for_test(responder_binding);

        let initiator = tokio::spawn(async move {
            handshake_initiator(&mut a_send, &mut a_recv, &alice, &initiator_binding).await
        });
        let responder = tokio::spawn(async move {
            handshake_responder(&mut b_send, &mut b_recv, &bob, &responder_binding).await
        });

        let relay = tokio::spawn(async move {
            let a_to_b = tokio::spawn(async move {
                let mut from = m_a_recv;
                let mut to = m_b_send;
                let copied = tokio::io::copy(&mut from, &mut to).await;
                // 关掉写半边，让对端能读到干净的 EOF 而不是干等。
                let _ = to.shutdown().await;
                copied
            });
            let b_to_a = tokio::spawn(async move {
                let mut from = m_b_recv;
                let mut to = m_a_send;
                let copied = tokio::io::copy(&mut from, &mut to).await;
                let _ = to.shutdown().await;
                copied
            });
            let _ = a_to_b.await;
            let _ = b_to_a.await;
        });

        let initiator_result = initiator.await.unwrap();
        let responder_result = responder.await.unwrap();
        relay.await.unwrap();

        if expect_success {
            assert!(
                initiator_result.is_ok(),
                "同会话转发应当成功: {initiator_result:?}"
            );
            assert!(
                responder_result.is_ok(),
                "同会话转发应当成功: {responder_result:?}"
            );
        } else {
            assert!(
                matches!(initiator_result, Err(Error::Identity(_))),
                "跨会话转发必须因签名校验失败而被拒绝，实际 {initiator_result:?}"
            );
            assert!(responder_result.is_err(), "跨会话转发不该完成认证");
        }
    }
}
