//! Session authorization follows Ed25519 identity and TLS exporter authentication.
//! Passwords exist only in zeroizing memory; only a versioned Argon2id verifier is persisted.
use std::{collections::HashMap, fmt, sync::Arc, time::Duration};

use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::{Mutex, Semaphore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::protocol::frame::{read_raw_frame_limited, write_raw_frame_limited};
use crate::{
    error::{Error, Result},
    identity::NodeId,
    transport::quic::ChannelBinding,
};

const VERSION: u16 = 1;
const MAGIC: &[u8; 5] = b"P2PA\x01";
const CONTEXT: &[u8] = b"p2p_file/desktop/remote-auth/v1";
const CONFIRM_CONTEXT: &[u8] = b"p2p_file/desktop/remote-auth/accepted/v1";
const AUTH_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_FAILURE_PEERS: usize = 256;
const FAILURE_TTL: Duration = Duration::from_secs(900);
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

fn invalid() -> Error {
    Error::Protocol("远程访问认证失败或暂时受限".into())
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| Error::Protocol("安全随机数不可用".into()))?;
    Ok(bytes)
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretPassword(String);
impl fmt::Debug for SecretPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretPassword([redacted])")
    }
}
impl SecretPassword {
    pub fn new(value: String) -> Result<Self> {
        let candidate = Self(value);
        if !(6..=12).contains(&candidate.0.len())
            || !candidate.0.bytes().all(|b| b.is_ascii_alphanumeric())
            || [
                "123456",
                "111111",
                "abcdef",
                "password",
                "000000",
                "12345678",
                "123456789",
                "qwerty",
            ]
            .iter()
            .any(|weak| candidate.0.eq_ignore_ascii_case(weak))
        {
            return Err(Error::Protocol(
                "密码须为 6～12 位字母或数字，且不能使用常见弱密码".into(),
            ));
        }
        Ok(candidate)
    }
    pub fn generate() -> Result<Self> {
        let mut value = String::with_capacity(10);
        while value.len() < 10 {
            let byte = random::<1>()?[0] as usize;
            let ceiling = 256 - 256 % ALPHABET.len();
            if byte < ceiling {
                value.push(ALPHABET[byte % ALPHABET.len()] as char);
            }
        }
        Self::new(value)
    }
    /// Explicit user display/copy only; never use for diagnostics.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct RemoteVerifier {
    version: u16,
    salt: [u8; 16],
    key: [u8; 32],
}
impl fmt::Debug for RemoteVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RemoteVerifier([redacted])")
    }
}
impl RemoteVerifier {
    pub fn create(password: &SecretPassword) -> Result<Self> {
        let salt = random()?;
        Ok(Self {
            version: VERSION,
            salt,
            key: derive(password, &salt)?,
        })
    }
    pub fn validate(&self) -> Result<()> {
        if self.version == VERSION {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}
fn derive(password: &SecretPassword, salt: &[u8; 16]) -> Result<[u8; 32]> {
    // Version 1 fixes m=19 MiB, t=2, p=1 (OWASP minimum); untrusted peers cannot choose costs.
    let params = Params::new(19 * 1024, 2, 1, Some(32)).map_err(|_| invalid())?;
    let mut key = [0; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.0.as_bytes(), salt, &mut key)
        .map_err(|_| invalid())?;
    Ok(key)
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Challenge {
    version: u16,
    salt: [u8; 16],
    nonce: [u8; 32],
}
impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Challenge([redacted])")
    }
}
impl Challenge {
    fn new(verifier: &RemoteVerifier) -> Result<Self> {
        verifier.validate()?;
        Ok(Self {
            version: VERSION,
            salt: verifier.salt,
            nonce: random()?,
        })
    }
}
#[derive(Serialize, Deserialize)]
enum AuthMessage {
    Challenge(Challenge),
    Proof(Option<[u8; 32]>),
    Result {
        accepted: bool,
        confirmation: Option<[u8; 32]>,
    },
}

fn mac(
    key: &[u8; 32],
    challenge: &Challenge,
    prover: NodeId,
    verifier: NodeId,
    binding: &[u8],
    context: &[u8],
) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts fixed 32 byte key");
    mac.update(context);
    mac.update(&challenge.version.to_le_bytes());
    mac.update(&challenge.salt);
    mac.update(&challenge.nonce);
    mac.update(prover.as_bytes());
    mac.update(verifier.as_bytes());
    mac.update(binding);
    mac
}
fn proof(
    key: &[u8; 32],
    challenge: &Challenge,
    prover: NodeId,
    verifier: NodeId,
    binding: &[u8],
) -> [u8; 32] {
    mac(key, challenge, prover, verifier, binding, CONTEXT)
        .finalize()
        .into_bytes()
        .into()
}
fn verify(
    key: &[u8; 32],
    challenge: &Challenge,
    prover: NodeId,
    verifier: NodeId,
    binding: &[u8],
    response: &[u8; 32],
) -> bool {
    mac(key, challenge, prover, verifier, binding, CONTEXT)
        .verify_slice(response)
        .is_ok()
}

/// Rights belong to the authenticated transport and expire with it. Stream replies
/// (including download data and TCP replies) remain part of the authorized request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RemoteAuthorization {
    pub inbound_authorized: bool,
    pub outbound_authorized: bool,
}
impl RemoteAuthorization {
    #[cfg(test)]
    pub const BOTH: Self = Self {
        inbound_authorized: true,
        outbound_authorized: true,
    };

    pub fn label(self) -> &'static str {
        match (self.inbound_authorized, self.outbound_authorized) {
            (true, true) => "双向访问已授权",
            (true, false) => "已允许对端访问；本机访问尚未授权",
            (false, true) => "本机访问对端已授权；对端访问未授权",
            (false, false) => "等待密码授权",
        }
    }
}

struct Failures {
    count: u32,
    seen: tokio::time::Instant,
    blocked_until: tokio::time::Instant,
}
#[derive(Default)]
struct FailureTable(HashMap<NodeId, Failures>);
impl FailureTable {
    fn prune(&mut self) {
        self.0.retain(|_, f| f.seen.elapsed() < FAILURE_TTL);
    }
    fn check(&mut self, peer: NodeId) -> Result<()> {
        self.prune();
        if self
            .0
            .get(&peer)
            .is_some_and(|f| f.blocked_until > tokio::time::Instant::now())
        {
            Err(invalid())
        } else {
            Ok(())
        }
    }
    fn failed(&mut self, peer: NodeId) -> Duration {
        self.prune();
        if !self.0.contains_key(&peer) && self.0.len() >= MAX_FAILURE_PEERS {
            // Expired entries were pruned first. Evict the least recently failed
            // identity rather than turning capacity into a global authentication ban.
            if let Some(oldest) = self.0.iter().min_by_key(|(_, f)| f.seen).map(|(id, _)| *id) {
                self.0.remove(&oldest);
            }
        }
        let now = tokio::time::Instant::now();
        let f = self.0.entry(peer).or_insert(Failures {
            count: 0,
            seen: now,
            blocked_until: now,
        });
        f.count = f.count.saturating_add(1);
        f.seen = now;
        let delay = match f.count {
            0..=3 => Duration::ZERO,
            4..=9 => Duration::from_millis(500 * (1 << (f.count - 4))),
            _ => Duration::from_secs(60),
        };
        f.blocked_until = now + delay;
        delay
    }
}

#[derive(Clone)]
pub struct AuthContext {
    failures: Arc<Mutex<FailureTable>>,
    kdf: Arc<Semaphore>,
}
impl Default for AuthContext {
    fn default() -> Self {
        Self {
            failures: Arc::new(Mutex::new(FailureTable::default())),
            kdf: Arc::new(Semaphore::new(2)),
        }
    }
}
impl AuthContext {
    /// Both directions exchange challenges because QUIC dialer order is unrelated to user intent.
    /// Return independent incoming and outgoing request rights. Neither right implies the other.
    /// A bare Result(true) never grants authorization.
    #[allow(clippy::too_many_arguments)]
    pub async fn authorize(
        &self,
        connection: &quinn::Connection,
        initiator: bool,
        local: NodeId,
        peer: NodeId,
        verifier: RemoteVerifier,
        password: Option<SecretPassword>,
        capabilities: u64,
    ) -> Result<RemoteAuthorization> {
        if capabilities & super::protocol::CAP_REMOTE_AUTH == 0 {
            return Err(Error::Protocol(
                "对端不支持远程访问认证，请升级客户端".into(),
            ));
        }
        self.failures.lock().await.check(peer)?;
        let result = tokio::time::timeout(
            AUTH_TIMEOUT,
            self.exchange(connection, initiator, local, peer, verifier, password),
        )
        .await;
        match result {
            Ok(Ok((authorization, failed_inbound))) => {
                if authorization.inbound_authorized {
                    self.failures.lock().await.0.remove(&peer);
                } else if failed_inbound {
                    let delay = self.failures.lock().await.failed(peer);
                    tokio::time::sleep(delay).await;
                }
                Ok(authorization)
            }
            _ => {
                let delay = self.failures.lock().await.failed(peer);
                // Delay is cancellable and consumes no blocking worker.
                tokio::time::sleep(delay).await;
                Err(invalid())
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    async fn exchange(
        &self,
        connection: &quinn::Connection,
        initiator: bool,
        local: NodeId,
        peer: NodeId,
        verifier: RemoteVerifier,
        password: Option<SecretPassword>,
    ) -> Result<(RemoteAuthorization, bool)> {
        let binding = ChannelBinding::from_connection(connection)?;
        let challenge = Challenge::new(&verifier)?;
        let (mut send, mut recv) = if initiator {
            connection.open_bi().await.map_err(|_| invalid())?
        } else {
            connection.accept_bi().await.map_err(|_| invalid())?
        };
        write(&mut send, &AuthMessage::Challenge(challenge.clone())).await?;
        let AuthMessage::Challenge(remote) = read(&mut recv).await? else {
            return Err(invalid());
        };
        if remote.version != VERSION {
            return Err(invalid());
        }
        let outgoing = if let Some(password) = password {
            let permit = self
                .kdf
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| invalid())?;
            let salt = remote.salt;
            let key = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                derive(&password, &salt).map(Zeroizing::new)
            })
            .await
            .map_err(|_| invalid())??;
            Some(key)
        } else {
            None
        };
        write(
            &mut send,
            &AuthMessage::Proof(
                outgoing
                    .as_ref()
                    .map(|key| proof(key, &remote, local, peer, binding.as_bytes())),
            ),
        )
        .await?;
        let AuthMessage::Proof(incoming) = read(&mut recv).await? else {
            return Err(invalid());
        };
        let accepted = incoming.is_some_and(|response| {
            verify(
                &verifier.key,
                &challenge,
                peer,
                local,
                binding.as_bytes(),
                &response,
            )
        });
        let confirmation = accepted.then(|| {
            mac(
                &verifier.key,
                &challenge,
                peer,
                local,
                binding.as_bytes(),
                CONFIRM_CONTEXT,
            )
            .finalize()
            .into_bytes()
            .into()
        });
        write(
            &mut send,
            &AuthMessage::Result {
                accepted,
                confirmation,
            },
        )
        .await?;
        let AuthMessage::Result {
            accepted: remote_accepted,
            confirmation: remote_confirmation,
        } = read(&mut recv).await?
        else {
            return Err(invalid());
        };
        send.finish().map_err(|_| invalid())?;
        let confirmed = remote_accepted
            && outgoing
                .as_ref()
                .zip(remote_confirmation.as_ref())
                .is_some_and(|(key, confirmation)| {
                    mac(
                        key,
                        &remote,
                        local,
                        peer,
                        binding.as_bytes(),
                        CONFIRM_CONTEXT,
                    )
                    .verify_slice(confirmation)
                    .is_ok()
                });
        if accepted || confirmed {
            Ok((
                RemoteAuthorization {
                    inbound_authorized: accepted,
                    outbound_authorized: confirmed,
                },
                incoming.is_some() && !accepted,
            ))
        } else {
            Err(invalid())
        }
    }
}
async fn write(send: &mut quinn::SendStream, message: &AuthMessage) -> Result<()> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend(postcard::to_allocvec(message)?);
    let result = write_raw_frame_limited(send, &bytes, 1024).await;
    bytes.zeroize();
    result
}
async fn read(recv: &mut quinn::RecvStream) -> Result<AuthMessage> {
    let mut bytes = read_raw_frame_limited(recv, 1024)
        .await?
        .ok_or_else(invalid)?;
    let result = bytes
        .strip_prefix(MAGIC)
        .ok_or_else(invalid)
        .and_then(|payload| postcard::take_from_bytes(payload).map_err(|_| invalid()))
        .map_err(|_| invalid())
        .and_then(|(message, trailing)| {
            if trailing.is_empty() {
                Ok(message)
            } else {
                Err(invalid())
            }
        });
    bytes.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn pair() -> (
        quinn::Endpoint,
        quinn::Endpoint,
        quinn::Connection,
        quinn::Connection,
    ) {
        use crate::transport::quic::{client_endpoint, connect, server_endpoint};
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let accepting = async { server.accept().await.unwrap().await.unwrap() };
        let (a, b) = tokio::join!(
            connect(&client, server.local_addr().unwrap(), "localhost"),
            accepting
        );
        (client, server, a.unwrap(), b)
    }
    #[tokio::test]
    async fn actual_quic_authorization_is_independent_of_password_and_dialer_direction() {
        let password = SecretPassword::new("A9b8C7".into()).unwrap();
        let verifier = RemoteVerifier::create(&password).unwrap();
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        for prover_is_dialer in [true, false] {
            let (_ce, _se, c, s) = pair().await;
            let ca = AuthContext::default();
            let sa = AuthContext::default();
            for _ in 0..3 {
                ca.failures.lock().await.failed(b);
                sa.failures.lock().await.failed(a);
            }
            let (left, right) = tokio::join!(
                ca.authorize(
                    &c,
                    true,
                    a,
                    b,
                    verifier.clone(),
                    prover_is_dialer.then(|| password.clone()),
                    super::super::protocol::LOCAL_CAPABILITIES
                ),
                sa.authorize(
                    &s,
                    false,
                    b,
                    a,
                    verifier.clone(),
                    (!prover_is_dialer).then(|| password.clone()),
                    super::super::protocol::LOCAL_CAPABILITIES
                )
            );
            assert_eq!(
                left.unwrap(),
                RemoteAuthorization {
                    inbound_authorized: !prover_is_dialer,
                    outbound_authorized: prover_is_dialer
                }
            );
            assert_eq!(
                right.unwrap(),
                RemoteAuthorization {
                    inbound_authorized: prover_is_dialer,
                    outbound_authorized: !prover_is_dialer
                }
            );
            assert_eq!(ca.failures.lock().await.0.is_empty(), !prover_is_dialer);
            assert_eq!(sa.failures.lock().await.0.is_empty(), prover_is_dialer);
        }
    }
    #[tokio::test]
    async fn both_directions_require_independent_password_proofs() {
        let pa = SecretPassword::new("Local9A".into()).unwrap();
        let pb = SecretPassword::new("Local9B".into()).unwrap();
        let va = RemoteVerifier::create(&pa).unwrap();
        let vb = RemoteVerifier::create(&pb).unwrap();
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        let (_ce, _se, c, s) = pair().await;
        let left = AuthContext::default();
        let right = AuthContext::default();
        let (ca, cb) = tokio::join!(
            left.authorize(
                &c,
                true,
                a,
                b,
                va,
                Some(pb),
                super::super::protocol::LOCAL_CAPABILITIES
            ),
            right.authorize(
                &s,
                false,
                b,
                a,
                vb,
                Some(pa),
                super::super::protocol::LOCAL_CAPABILITIES
            ),
        );
        assert_eq!(ca.unwrap(), RemoteAuthorization::BOTH);
        assert_eq!(cb.unwrap(), RemoteAuthorization::BOTH);
    }

    #[tokio::test]
    async fn successful_outgoing_confirmation_does_not_clear_wrong_incoming_proof_failures() {
        let pa = SecretPassword::new("Local9A".into()).unwrap();
        let pb = SecretPassword::new("Local9B".into()).unwrap();
        let wrong = SecretPassword::new("Wrong9A".into()).unwrap();
        let va = RemoteVerifier::create(&pa).unwrap();
        let vb = RemoteVerifier::create(&pb).unwrap();
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        let left = AuthContext::default();
        let right = AuthContext::default();
        for count in 1..=3 {
            let (_ce, _se, c, s) = pair().await;
            let (ca, cb) = tokio::join!(
                left.authorize(
                    &c,
                    true,
                    a,
                    b,
                    va.clone(),
                    Some(pb.clone()),
                    super::super::protocol::LOCAL_CAPABILITIES
                ),
                right.authorize(
                    &s,
                    false,
                    b,
                    a,
                    vb.clone(),
                    Some(wrong.clone()),
                    super::super::protocol::LOCAL_CAPABILITIES
                ),
            );
            assert_eq!(
                ca.unwrap(),
                RemoteAuthorization {
                    inbound_authorized: false,
                    outbound_authorized: true
                }
            );
            assert_eq!(
                cb.unwrap(),
                RemoteAuthorization {
                    inbound_authorized: true,
                    outbound_authorized: false
                }
            );
            assert_eq!(left.failures.lock().await.0[&b].count, count);
        }
    }

    #[tokio::test]
    async fn a_full_failure_table_does_not_block_a_new_correctly_authenticating_peer() {
        let context = AuthContext::default();
        for _ in 0..MAX_FAILURE_PEERS {
            context
                .failures
                .lock()
                .await
                .failed(crate::identity::Identity::generate().node_id());
        }
        assert_eq!(context.failures.lock().await.0.len(), MAX_FAILURE_PEERS);
        let password = SecretPassword::new("Normal9".into()).unwrap();
        let verifier = RemoteVerifier::create(&password).unwrap();
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        let (_ce, _se, c, s) = pair().await;
        let other = AuthContext::default();
        let (ca, cb) = tokio::join!(
            other.authorize(
                &c,
                true,
                a,
                b,
                verifier.clone(),
                Some(password),
                super::super::protocol::LOCAL_CAPABILITIES
            ),
            context.authorize(
                &s,
                false,
                b,
                a,
                verifier,
                None,
                super::super::protocol::LOCAL_CAPABILITIES
            ),
        );
        assert!(ca.unwrap().outbound_authorized);
        assert!(cb.unwrap().inbound_authorized);
        assert!(context.failures.lock().await.0.len() <= MAX_FAILURE_PEERS);
        context.failures.lock().await.failed(a);
        assert_eq!(context.failures.lock().await.0.len(), MAX_FAILURE_PEERS);
        assert!(context.failures.lock().await.0.contains_key(&a));
    }

    #[tokio::test]
    async fn wrong_or_absent_password_and_old_capability_never_authorize() {
        let password = SecretPassword::new("A9b8C7".into()).unwrap();
        let verifier = RemoteVerifier::create(&password).unwrap();
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        for outgoing in [None, Some(SecretPassword::new("Wrong7".into()).unwrap())] {
            let (_ce, _se, c, s) = pair().await;
            let ca = AuthContext::default();
            let sa = AuthContext::default();
            let (left, right) = tokio::join!(
                ca.authorize(
                    &c,
                    true,
                    a,
                    b,
                    verifier.clone(),
                    outgoing,
                    super::super::protocol::LOCAL_CAPABILITIES
                ),
                sa.authorize(
                    &s,
                    false,
                    b,
                    a,
                    verifier.clone(),
                    None,
                    super::super::protocol::LOCAL_CAPABILITIES
                )
            );
            assert!(left.is_err());
            assert!(right.is_err());
        }
        let (_ce, _se, c, _s) = pair().await;
        assert!(
            AuthContext::default()
                .authorize(
                    &c,
                    true,
                    a,
                    b,
                    verifier,
                    None,
                    super::super::protocol::REQUIRED_CAPABILITIES
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("升级")
        );
    }
    #[tokio::test]
    async fn forged_success_and_business_frame_before_auth_are_rejected() {
        let password = SecretPassword::new("A9b8C7".into()).unwrap();
        let verifier = RemoteVerifier::create(&password).unwrap();
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        for (business, submit_password) in [(false, false), (false, true), (true, false)] {
            let (_ce, _se, c, s) = pair().await;
            let attack = async {
                let (mut send, mut recv) = s.accept_bi().await.unwrap();
                if business {
                    super::super::protocol::write(
                        &mut send,
                        &super::super::protocol::Frame {
                            request_id: 0,
                            message: super::super::protocol::Message::TunnelOpen {
                                target: "127.0.0.1:22".parse().unwrap(),
                            },
                        },
                    )
                    .await
                    .unwrap();
                    let _ = send.finish();
                    return;
                }
                let _ = read(&mut recv).await.unwrap();
                write(
                    &mut send,
                    &AuthMessage::Challenge(Challenge::new(&verifier).unwrap()),
                )
                .await
                .unwrap();
                let AuthMessage::Proof(captured) = read(&mut recv).await.unwrap() else {
                    panic!("expected proof");
                };
                write(&mut send, &AuthMessage::Proof(None)).await.unwrap();
                let _ = read(&mut recv).await.unwrap();
                write(
                    &mut send,
                    &AuthMessage::Result {
                        accepted: true,
                        confirmation: captured,
                    },
                )
                .await
                .unwrap();
                let _ = send.finish();
            };
            let ctx = AuthContext::default();
            let (result, ()) = tokio::join!(
                ctx.authorize(
                    &c,
                    true,
                    a,
                    b,
                    verifier.clone(),
                    submit_password.then(|| password.clone()),
                    super::super::protocol::LOCAL_CAPABILITIES
                ),
                attack
            );
            assert!(result.is_err());
        }
    }
    #[tokio::test]
    async fn stalled_auth_is_bounded_and_failure_cooldown_does_not_block_other_peer() {
        let password = SecretPassword::new("A9b8C7".into()).unwrap();
        let verifier = RemoteVerifier::create(&password).unwrap();
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        let (_ce, _se, c, s) = pair().await;
        let context = AuthContext::default();
        let task_context = context.clone();
        let task = tokio::spawn(async move {
            task_context
                .authorize(
                    &c,
                    true,
                    a,
                    b,
                    verifier,
                    None,
                    super::super::protocol::LOCAL_CAPABILITIES,
                )
                .await
        });
        let (_send, _recv) = s.accept_bi().await.unwrap();
        tokio::time::pause();
        tokio::time::advance(AUTH_TIMEOUT + Duration::from_secs(1)).await;
        assert!(task.await.unwrap().is_err());
        let mut failures = context.failures.lock().await;
        failures.0.clear();
        for _ in 0..10 {
            failures.failed(a);
        }
        assert!(failures.check(a).is_err());
        assert!(failures.check(b).is_ok());
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(failures.check(a).is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(failures.check(a).is_ok());
    }
    #[test]
    fn unsupported_verifier_and_challenge_versions_cannot_reuse_proofs() {
        let password = SecretPassword::new("A9b8C7".into()).unwrap();
        let mut verifier = RemoteVerifier::create(&password).unwrap();
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        let mut challenge = Challenge::new(&verifier).unwrap();
        let response = proof(&verifier.key, &challenge, a, b, &[3; 32]);
        challenge.version = 2;
        assert!(!verify(
            &verifier.key,
            &challenge,
            a,
            b,
            &[3; 32],
            &response
        ));
        verifier.version = 2;
        assert!(verifier.validate().is_err());
        assert!(Challenge::new(&verifier).is_err());
    }
    #[test]
    fn password_policy_generation_and_redaction() {
        for bad in [
            "123456",
            "111111",
            "abcdef",
            "password",
            "000000",
            "abcde",
            "abcdefghijklm",
            "abc 中文",
            "abc\n12",
        ] {
            assert!(SecretPassword::new(bad.into()).is_err());
        }
        for _ in 0..100 {
            let p = SecretPassword::generate().unwrap();
            assert_eq!(p.expose().len(), 10);
            assert!(p.expose().bytes().all(|b| ALPHABET.contains(&b)));
            assert!(!format!("{p:?}").contains(p.expose()));
        }
        assert!(SecretPassword::new("A9b8C7".into()).is_ok());
        for length in 6..=12 {
            assert!(SecretPassword::new(format!("{}9", "A".repeat(length - 1))).is_ok());
        }
        assert!(SecretPassword::new("246802".into()).is_ok());
        assert!(SecretPassword::new("GhJkMn".into()).is_ok());
    }
    #[test]
    fn proof_binds_password_nonce_identities_and_session() {
        let password = SecretPassword::new("A9b8C7".into()).unwrap();
        let verifier = RemoteVerifier::create(&password).unwrap();
        let challenge = Challenge::new(&verifier).unwrap();
        let a = NodeId::from_hex(&"01".repeat(16)).unwrap();
        let b = NodeId::from_hex(&"02".repeat(16)).unwrap();
        let binding = [3; 32];
        let key = derive(&password, &challenge.salt).unwrap();
        let response = proof(&key, &challenge, a, b, &binding);
        assert!(verify(&verifier.key, &challenge, a, b, &binding, &response));
        assert!(!verify(
            &verifier.key,
            &Challenge::new(&verifier).unwrap(),
            a,
            b,
            &binding,
            &response
        ));
        assert!(!verify(
            &verifier.key,
            &challenge,
            b,
            a,
            &binding,
            &response
        ));
        assert!(!verify(
            &verifier.key,
            &challenge,
            a,
            b,
            &[4; 32],
            &response
        ));
        let wrong = derive(
            &SecretPassword::new("Wrong7".into()).unwrap(),
            &challenge.salt,
        )
        .unwrap();
        assert!(!verify(&wrong, &challenge, a, b, &binding, &response));
        let json = serde_json::to_string(&verifier).unwrap();
        assert!(!json.contains(password.expose()));
        assert_eq!(format!("{verifier:?}"), "RemoteVerifier([redacted])");
    }
    #[tokio::test(start_paused = true)]
    async fn failures_are_peer_scoped_bounded_and_expire() {
        let mut table = FailureTable::default();
        let a = NodeId::from_hex(&"01".repeat(16)).unwrap();
        let b = NodeId::from_hex(&"02".repeat(16)).unwrap();
        for _ in 0..3 {
            assert_eq!(table.failed(a), Duration::ZERO);
        }
        assert_eq!(table.failed(a), Duration::from_millis(500));
        assert!(table.check(a).is_err());
        assert!(table.check(b).is_ok());
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(table.failed(a), Duration::from_secs(1));
        for n in 0..MAX_FAILURE_PEERS {
            let mut id = [0; 16];
            id[..8].copy_from_slice(&(n as u64).to_le_bytes());
            table.failed(NodeId::from_hex(&hex::encode(id)).unwrap());
        }
        assert_eq!(table.0.len(), MAX_FAILURE_PEERS);
        assert!(
            table
                .check(NodeId::from_hex(&"ff".repeat(16)).unwrap())
                .is_ok()
        );
        tokio::time::advance(FAILURE_TTL).await;
        assert!(table.check(a).is_ok());
        assert!(table.0.is_empty());
    }
}
