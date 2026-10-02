//! Session authorization follows Ed25519 identity and TLS exporter authentication.
//! Passwords exist only in zeroizing memory; only a versioned Argon2id verifier is persisted.
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
    time::Duration,
};

use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::{Mutex, Semaphore, watch};
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
    TrustedGrant {
        accepted: bool,
        sequence: u64,
        confirmation: [u8; 32],
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
pub struct AuthorizationGrant {
    pub password: bool,
    pub trusted_device: bool,
}
impl AuthorizationGrant {
    pub const fn password(password: bool) -> Self {
        Self {
            password,
            trusted_device: false,
        }
    }
    pub const fn authorized(self) -> bool {
        self.password || self.trusted_device
    }
    pub fn label(self) -> &'static str {
        match (self.password, self.trusted_device) {
            (true, true) => "密码及可信设备",
            (true, false) => "密码",
            (false, true) => "可信设备",
            (false, false) => "未授权",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RemoteAuthorization {
    pub inbound: AuthorizationGrant,
    pub outbound: AuthorizationGrant,
}
impl RemoteAuthorization {
    #[cfg(test)]
    pub const BOTH: Self = Self {
        inbound: AuthorizationGrant::password(true),
        outbound: AuthorizationGrant::password(true),
    };
    pub const fn inbound_authorized(self) -> bool {
        self.inbound.authorized()
    }
    pub const fn outbound_authorized(self) -> bool {
        self.outbound.authorized()
    }
    pub fn label(self) -> String {
        format!(
            "对端访问本机：{}；本机访问对端：{}",
            self.inbound.label(),
            self.outbound.label()
        )
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

#[cfg(test)]
type PublishGate = Arc<
    std::sync::Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
>;

#[derive(Clone)]
pub struct AuthContext {
    failures: Arc<Mutex<FailureTable>>,
    kdf: Arc<Semaphore>,
    trusted: watch::Sender<HashSet<NodeId>>,
    #[cfg(test)]
    publish_gate: PublishGate,
}
impl Default for AuthContext {
    fn default() -> Self {
        Self {
            failures: Arc::new(Mutex::new(FailureTable::default())),
            kdf: Arc::new(Semaphore::new(2)),
            trusted: watch::channel(HashSet::new()).0,
            #[cfg(test)]
            publish_gate: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}
impl AuthContext {
    pub fn set_trusted(&self, devices: &[super::trusted_devices::TrustedDevice]) {
        self.trusted.send_replace(
            devices
                .iter()
                .filter_map(|d| NodeId::from_hex(&d.node_id).ok())
                .collect(),
        );
    }
    pub fn trusts(&self, peer: NodeId) -> bool {
        self.trusted.borrow().contains(&peer)
    }
    #[cfg(test)]
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
        self.authorize_session(
            connection,
            initiator,
            local,
            peer,
            verifier,
            password,
            capabilities,
        )
        .await
        .map(|s| s.authorization)
    }
    /// Both directions exchange challenges because QUIC dialer order is unrelated to user intent.
    /// Return independent incoming and outgoing request rights. Neither right implies the other.
    /// A bare Result(true) never grants authorization.
    #[allow(clippy::too_many_arguments)]
    pub async fn authorize_session(
        &self,
        connection: &quinn::Connection,
        initiator: bool,
        local: NodeId,
        peer: NodeId,
        verifier: RemoteVerifier,
        password: Option<SecretPassword>,
        capabilities: u64,
    ) -> Result<AuthorizedSession> {
        if capabilities & super::protocol::CAP_REMOTE_AUTH == 0 {
            return Err(Error::Protocol(
                "对端不支持远程访问认证，请升级客户端".into(),
            ));
        }
        self.failures.lock().await.check(peer)?;
        let result = tokio::time::timeout(
            AUTH_TIMEOUT,
            self.exchange(
                connection,
                initiator,
                local,
                peer,
                verifier,
                password,
                capabilities,
            ),
        )
        .await;
        match result {
            Ok(Ok((mut session, failed_inbound))) => {
                #[cfg(test)]
                {
                    let gate = self.publish_gate.lock().unwrap().take();
                    if let Some((reached, release)) = gate {
                        let _ = reached.send(());
                        let _ = release.await;
                    }
                }
                session.authorization.inbound.trusted_device &= self.trusts(peer);
                if !session.authorization.inbound_authorized()
                    && !session.authorization.outbound_authorized()
                {
                    return Err(invalid());
                }
                if session.authorization.inbound.password {
                    self.failures.lock().await.0.remove(&peer);
                } else if failed_inbound {
                    let delay = self.failures.lock().await.failed(peer);
                    tokio::time::sleep(delay).await;
                }
                Ok(session)
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
        capabilities: u64,
    ) -> Result<(AuthorizedSession, bool)> {
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
        let mut authorization = RemoteAuthorization {
            inbound: AuthorizationGrant::password(accepted),
            outbound: AuthorizationGrant::password(confirmed),
        };
        let control = if capabilities & super::protocol::CAP_TRUSTED_DEVICE_AUTH != 0 {
            let trusted = self.trusted.subscribe();
            authorization.inbound.trusted_device = trusted.borrow().contains(&peer);
            let mut control = TrustedControl {
                send,
                recv: Some(recv),
                binding,
                challenge,
                remote,
                local,
                peer,
                trusted,
                sent_sequence: 0,
                received_sequence: 0,
            };
            control
                .send_grant(authorization.inbound.trusted_device)
                .await?;
            authorization.outbound.trusted_device = control.receive_grant(0).await?;
            Some(control)
        } else {
            send.finish().map_err(|_| invalid())?;
            None
        };
        if authorization.inbound_authorized() || authorization.outbound_authorized() {
            Ok((
                AuthorizedSession {
                    authorization,
                    control,
                },
                incoming.is_some() && !accepted,
            ))
        } else {
            Err(invalid())
        }
    }
}
pub struct AuthorizedSession {
    pub authorization: RemoteAuthorization,
    pub control: Option<TrustedControl>,
}

pub struct TrustedControl {
    send: quinn::SendStream,
    recv: Option<quinn::RecvStream>,
    binding: ChannelBinding,
    challenge: Challenge,
    remote: Challenge,
    local: NodeId,
    peer: NodeId,
    trusted: watch::Receiver<HashSet<NodeId>>,
    sent_sequence: u64,
    received_sequence: u64,
}
fn trusted_mac(
    binding: &ChannelBinding,
    challenge: &Challenge,
    grantor: NodeId,
    recipient: NodeId,
    accepted: bool,
    sequence: u64,
) -> Hmac<Sha256> {
    let mut mac = mac(
        binding.as_bytes(),
        challenge,
        recipient,
        grantor,
        binding.as_bytes(),
        b"p2p_file/desktop/trusted-device/v1",
    );
    mac.update(&sequence.to_le_bytes());
    mac.update(&[u8::from(accepted)]);
    mac
}
impl TrustedControl {
    async fn send_grant(&mut self, accepted: bool) -> Result<()> {
        let confirmation = trusted_mac(
            &self.binding,
            &self.challenge,
            self.local,
            self.peer,
            accepted,
            self.sent_sequence,
        )
        .finalize()
        .into_bytes()
        .into();
        tokio::time::timeout(
            Duration::from_secs(5),
            write(
                &mut self.send,
                &AuthMessage::TrustedGrant {
                    accepted,
                    sequence: self.sent_sequence,
                    confirmation,
                },
            ),
        )
        .await
        .map_err(|_| invalid())?
    }
    async fn receive_grant(&mut self, expected: u64) -> Result<bool> {
        let AuthMessage::TrustedGrant {
            accepted,
            sequence,
            confirmation,
        } = read(self.recv.as_mut().ok_or_else(invalid)?).await?
        else {
            return Err(invalid());
        };
        if sequence != expected
            || trusted_mac(
                &self.binding,
                &self.remote,
                self.peer,
                self.local,
                accepted,
                sequence,
            )
            .verify_slice(&confirmation)
            .is_err()
        {
            return Err(invalid());
        }
        Ok(accepted)
    }
    /// This stream is owned by exactly one authenticated QUIC connection. Closing
    /// or corrupting it removes only trust grants; password proofs stay valid.
    pub async fn run(mut self, changes: AuthorizationPublisher) {
        // Frame reads must survive a simultaneous local policy change. Cancelling
        // read_exact mid-frame would discard framing bytes and desynchronize the stream.
        let mut reader = tokio::task::JoinSet::new();
        let (messages, mut incoming) = tokio::sync::mpsc::channel(1);
        let mut recv = self.recv.take().expect("control owns its receive stream");
        reader.spawn(async move {
            loop {
                let message = read(&mut recv).await;
                let failed = message.is_err();
                if messages.send(message).await.is_err() || failed {
                    break;
                }
            }
            let _ = recv.stop(4u32.into());
        });
        let result: Result<()> = async {
            loop {
                let expected = self.received_sequence.checked_add(1).ok_or_else(invalid)?;
                tokio::select! {
                    biased;
                    changed = self.trusted.changed() => {
                        changed.map_err(|_| invalid())?;
                        let accepted = self.trusted.borrow_and_update().contains(&self.peer);
                        self.sent_sequence = self.sent_sequence.checked_add(1).ok_or_else(invalid)?;
                        self.send_grant(accepted).await?;
                        changes.send_modify(|a| a.inbound.trusted_device = accepted);
                    }
                    received = incoming.recv() => {
                        let AuthMessage::TrustedGrant { accepted, sequence, confirmation } = received.ok_or_else(invalid)?? else { return Err(invalid()); };
                        if sequence != expected || trusted_mac(&self.binding, &self.remote, self.peer, self.local, accepted, sequence).verify_slice(&confirmation).is_err() { return Err(invalid()); }
                        self.received_sequence = expected;
                        changes.send_modify(|a| a.outbound.trusted_device = accepted);
                    }
                }
            }
        }.await;
        let _ = result;
        changes.send_modify(|a| {
            a.inbound.trusted_device = false;
            a.outbound.trusted_device = false;
        });
        let _ = self.send.reset(4u32.into());
        reader.abort_all();
        while reader.join_next().await.is_some() {}
    }
}

#[derive(Default)]
pub struct RevocationEpochs {
    inbound: std::sync::atomic::AtomicU64,
    outbound: std::sync::atomic::AtomicU64,
}
impl RevocationEpochs {
    fn get(&self, inbound: bool) -> u64 {
        if inbound {
            &self.inbound
        } else {
            &self.outbound
        }
        .load(std::sync::atomic::Ordering::Acquire)
    }
    fn changed(&self, before: RemoteAuthorization, after: RemoteAuthorization) {
        use std::sync::atomic::Ordering;
        if before.inbound_authorized() && !after.inbound_authorized() {
            self.inbound.fetch_add(1, Ordering::AcqRel);
        }
        if before.outbound_authorized() && !after.outbound_authorized() {
            self.outbound.fetch_add(1, Ordering::AcqRel);
        }
    }
}
/// A monotonic revocation epoch prevents watch coalescing from hiding revoke/regrant
/// from a running stream. Effective Password grants do not advance that direction.
#[derive(Clone)]
pub struct AuthorizationPublisher {
    sender: watch::Sender<RemoteAuthorization>,
    epochs: Arc<RevocationEpochs>,
}
impl AuthorizationPublisher {
    pub fn new(authorization: RemoteAuthorization) -> Self {
        Self {
            sender: watch::channel(authorization).0,
            epochs: Arc::new(RevocationEpochs::default()),
        }
    }
    pub fn borrow(&self) -> watch::Ref<'_, RemoteAuthorization> {
        self.sender.borrow()
    }
    pub fn subscribe(&self) -> watch::Receiver<RemoteAuthorization> {
        self.sender.subscribe()
    }
    pub fn live(&self) -> LiveAuthorization {
        LiveAuthorization::Live(self.subscribe(), self.epochs.clone())
    }
    pub fn send_modify(&self, update: impl FnOnce(&mut RemoteAuthorization)) {
        self.sender.send_modify(|authorization| {
            let old = *authorization;
            update(authorization);
            self.epochs.changed(old, *authorization);
        });
    }
    pub fn send_if_modified(&self, update: impl FnOnce(&mut RemoteAuthorization) -> bool) {
        self.sender.send_if_modified(|authorization| {
            let old = *authorization;
            let changed = update(authorization);
            if changed {
                self.epochs.changed(old, *authorization);
            }
            changed
        });
    }
    pub fn send_replace(&self, authorization: RemoteAuthorization) {
        self.send_modify(|a| *a = authorization);
    }
}

/// Readable rights belong to this connection, never to a peer cache or a new generation.
#[derive(Clone)]
pub enum LiveAuthorization {
    Live(watch::Receiver<RemoteAuthorization>, Arc<RevocationEpochs>),
    #[cfg(test)]
    Fixed(RemoteAuthorization),
}
impl LiveAuthorization {
    pub fn current(&self) -> RemoteAuthorization {
        match self {
            Self::Live(receiver, _) => *receiver.borrow(),
            #[cfg(test)]
            Self::Fixed(a) => *a,
        }
    }
    pub async fn denied(&mut self, inbound: bool) {
        let epoch = match self {
            Self::Live(_, epochs) => epochs.get(inbound),
            #[cfg(test)]
            Self::Fixed(_) => 0,
        };
        loop {
            let authorized = if inbound {
                self.current().inbound_authorized()
            } else {
                self.current().outbound_authorized()
            };
            if !authorized {
                return;
            }
            match self {
                Self::Live(receiver, epochs) => {
                    if epochs.get(inbound) != epoch {
                        return;
                    }
                    if receiver.changed().await.is_err() {
                        return;
                    }
                }
                #[cfg(test)]
                Self::Fixed(_) => std::future::pending::<()>().await,
            }
        }
    }
    pub async fn guard<T>(
        &self,
        inbound: bool,
        work: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        let mut rights = self.clone();
        tokio::select! { biased; _ = rights.denied(inbound) => Err(Error::Protocol("当前方向的远程授权已撤销".into())), result = work => result }
    }
}
#[cfg(test)]
impl From<RemoteAuthorization> for LiveAuthorization {
    fn from(a: RemoteAuthorization) -> Self {
        Self::Fixed(a)
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
                    inbound: crate::desktop::remote_auth::AuthorizationGrant::password(
                        !prover_is_dialer
                    ),
                    outbound: crate::desktop::remote_auth::AuthorizationGrant::password(
                        prover_is_dialer
                    )
                }
            );
            assert_eq!(
                right.unwrap(),
                RemoteAuthorization {
                    inbound: crate::desktop::remote_auth::AuthorizationGrant::password(
                        prover_is_dialer
                    ),
                    outbound: crate::desktop::remote_auth::AuthorizationGrant::password(
                        !prover_is_dialer
                    )
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
                    inbound: crate::desktop::remote_auth::AuthorizationGrant::password(false),
                    outbound: crate::desktop::remote_auth::AuthorizationGrant::password(true)
                }
            );
            assert_eq!(
                cb.unwrap(),
                RemoteAuthorization {
                    inbound: crate::desktop::remote_auth::AuthorizationGrant::password(true),
                    outbound: crate::desktop::remote_auth::AuthorizationGrant::password(false)
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
        assert!(ca.unwrap().outbound_authorized());
        assert!(cb.unwrap().inbound_authorized());
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
    fn trust(peer: NodeId) -> super::super::trusted_devices::TrustedDevice {
        super::super::trusted_devices::TrustedDevice::new(
            peer,
            "test device".into(),
            Some("100000124".into()),
        )
    }
    async fn wait_rights(
        receiver: &mut watch::Receiver<RemoteAuthorization>,
        expected: RemoteAuthorization,
    ) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while *receiver.borrow_and_update() != expected {
                receiver.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn trusted_only_is_one_way_and_preserves_password_failure_statistics() {
        let (_ce, _se, c, s) = pair().await;
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        let ca = AuthContext::default();
        let sa = AuthContext::default();
        sa.set_trusted(&[trust(a)]);
        sa.failures.lock().await.failed(a);
        let verifier =
            RemoteVerifier::create(&SecretPassword::new("A9b8C7".into()).unwrap()).unwrap();
        let caps = super::super::protocol::LOCAL_CAPABILITIES;
        let (left, right) = tokio::join!(
            ca.authorize_session(&c, true, a, b, verifier.clone(), None, caps),
            sa.authorize_session(&s, false, b, a, verifier, None, caps)
        );
        let left = left.unwrap();
        let right = right.unwrap();
        assert!(!left.authorization.inbound_authorized());
        assert_eq!(
            left.authorization.outbound,
            AuthorizationGrant {
                password: false,
                trusted_device: true
            }
        );
        assert_eq!(right.authorization.inbound, left.authorization.outbound);
        assert!(!right.authorization.outbound_authorized());
        assert!(!ca.trusts(b));
        assert_eq!(sa.failures.lock().await.0[&a].count, 1);
        let ltx = AuthorizationPublisher::new(left.authorization);
        let mut lrx = ltx.subscribe();
        let rtx = AuthorizationPublisher::new(right.authorization);
        let mut rrx = rtx.subscribe();
        let ltask = tokio::spawn(left.control.unwrap().run(ltx));
        let rtask = tokio::spawn(right.control.unwrap().run(rtx));
        sa.set_trusted(&[]);
        wait_rights(&mut lrx, RemoteAuthorization::default()).await;
        wait_rights(&mut rrx, RemoteAuthorization::default()).await;
        assert_eq!(sa.failures.lock().await.0[&a].count, 1);
        ltask.abort();
        rtask.abort();
    }
    #[tokio::test]
    async fn mixed_grants_revoke_only_trust_and_control_failure_keeps_password() {
        let (_ce, _se, c, s) = pair().await;
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        let ca = AuthContext::default();
        let sa = AuthContext::default();
        sa.set_trusted(&[trust(a)]);
        let password = SecretPassword::new("A9b8C7".into()).unwrap();
        let verifier = RemoteVerifier::create(&password).unwrap();
        let caps = super::super::protocol::LOCAL_CAPABILITIES;
        let (left, right) = tokio::join!(
            ca.authorize_session(&c, true, a, b, verifier.clone(), Some(password), caps),
            sa.authorize_session(&s, false, b, a, verifier, None, caps)
        );
        let left = left.unwrap();
        let right = right.unwrap();
        assert_eq!(
            left.authorization.outbound,
            AuthorizationGrant {
                password: true,
                trusted_device: true
            }
        );
        let ltx = AuthorizationPublisher::new(left.authorization);
        let mut lrx = ltx.subscribe();
        let rtx = AuthorizationPublisher::new(right.authorization);
        let mut rrx = rtx.subscribe();
        let ltask = tokio::spawn(left.control.unwrap().run(ltx));
        let rtask = tokio::spawn(right.control.unwrap().run(rtx));
        sa.set_trusted(&[]);
        let expected_left = RemoteAuthorization {
            inbound: AuthorizationGrant::default(),
            outbound: AuthorizationGrant::password(true),
        };
        let expected_right = RemoteAuthorization {
            inbound: AuthorizationGrant::password(true),
            outbound: AuthorizationGrant::default(),
        };
        wait_rights(&mut lrx, expected_left).await;
        wait_rights(&mut rrx, expected_right).await;
        sa.set_trusted(&[trust(a)]);
        wait_rights(&mut lrx, left.authorization).await;
        rtask.abort();
        wait_rights(&mut lrx, expected_left).await;
        assert_eq!(c.close_reason(), None);
        ltask.abort();
    }
    #[tokio::test]
    async fn legacy_capability_requires_password_and_never_silently_trusts() {
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        let ca = AuthContext::default();
        let sa = AuthContext::default();
        sa.set_trusted(&[trust(a)]);
        let password = SecretPassword::new("A9b8C7".into()).unwrap();
        let verifier = RemoteVerifier::create(&password).unwrap();
        let caps = super::super::protocol::LOCAL_CAPABILITIES
            & !super::super::protocol::CAP_TRUSTED_DEVICE_AUTH;
        for use_password in [false, true] {
            let (_ce, _se, c, s) = pair().await;
            let (left, right) = tokio::join!(
                ca.authorize_session(
                    &c,
                    true,
                    a,
                    b,
                    verifier.clone(),
                    use_password.then(|| password.clone()),
                    caps
                ),
                sa.authorize_session(&s, false, b, a, verifier.clone(), None, caps)
            );
            if !use_password {
                assert!(left.is_err() && right.is_err());
            } else {
                let left = left.unwrap();
                let right = right.unwrap();
                assert!(left.control.is_none() && right.control.is_none());
                assert_eq!(
                    left.authorization.outbound,
                    AuthorizationGrant::password(true)
                );
            }
        }
    }
    #[tokio::test]
    async fn trusted_confirmation_cannot_cross_identity_session_challenge_or_sequence() {
        let (_c1, _s1, c1, _) = pair().await;
        let (_c2, _s2, c2, _) = pair().await;
        let b1 = ChannelBinding::from_connection(&c1).unwrap();
        let b2 = ChannelBinding::from_connection(&c2).unwrap();
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        let other = crate::identity::Identity::generate().node_id();
        let verifier =
            RemoteVerifier::create(&SecretPassword::new("A9b8C7".into()).unwrap()).unwrap();
        let challenge = Challenge::new(&verifier).unwrap();
        let fresh = Challenge::new(&verifier).unwrap();
        let proof = trusted_mac(&b1, &challenge, b, a, true, 0)
            .finalize()
            .into_bytes();
        assert!(
            trusted_mac(&b1, &challenge, b, a, true, 0)
                .verify_slice(&proof)
                .is_ok()
        );
        for mac in [
            trusted_mac(&b2, &challenge, b, a, true, 0),
            trusted_mac(&b1, &fresh, b, a, true, 0),
            trusted_mac(&b1, &challenge, b, other, true, 0),
            trusted_mac(&b1, &challenge, b, a, false, 0),
            trusted_mac(&b1, &challenge, b, a, true, 1),
        ] {
            assert!(mac.verify_slice(&proof).is_err());
        }
    }
    #[tokio::test]
    async fn live_direction_revocation_cancels_work_without_killing_password_direction() {
        let mixed = RemoteAuthorization {
            inbound: AuthorizationGrant {
                password: false,
                trusted_device: true,
            },
            outbound: AuthorizationGrant {
                password: true,
                trusted_device: true,
            },
        };
        let sender = AuthorizationPublisher::new(mixed);
        let live = sender.live();
        let incoming = tokio::spawn({
            let live = live.clone();
            async move { live.guard(true, std::future::pending::<Result<()>>()).await }
        });
        sender.send_modify(|a| {
            a.inbound.trusted_device = false;
            a.outbound.trusted_device = false;
        });
        assert!(
            tokio::time::timeout(Duration::from_secs(1), incoming)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(live.guard(false, async { Ok(()) }).await.is_ok());
        assert!(!live.current().inbound_authorized());
        assert!(live.current().outbound_authorized());
    }
    #[tokio::test]
    async fn revocation_during_authentication_cannot_publish_a_stale_trusted_grant() {
        let (_ce, _se, c, s) = pair().await;
        let a = crate::identity::Identity::generate().node_id();
        let b = crate::identity::Identity::generate().node_id();
        let ca = AuthContext::default();
        let sa = AuthContext::default();
        sa.set_trusted(&[trust(a)]);
        let (reached, waiting) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        *sa.publish_gate.lock().unwrap() = Some((reached, released));
        let verifier =
            RemoteVerifier::create(&SecretPassword::new("A9b8C7".into()).unwrap()).unwrap();
        let caps = super::super::protocol::LOCAL_CAPABILITIES;
        let server_auth = tokio::spawn({
            let sa = sa.clone();
            let verifier = verifier.clone();
            async move {
                sa.authorize_session(&s, false, b, a, verifier, None, caps)
                    .await
            }
        });
        let client_auth = tokio::spawn(async move {
            ca.authorize_session(&c, true, a, b, verifier, None, caps)
                .await
        });
        waiting.await.unwrap();
        sa.set_trusted(&[]);
        release.send(()).unwrap();
        assert!(server_auth.await.unwrap().is_err());
        let client = client_auth.await.unwrap().unwrap();
        let rights = AuthorizationPublisher::new(client.authorization);
        let mut changes = rights.subscribe();
        let control = tokio::spawn(client.control.unwrap().run(rights));
        wait_rights(&mut changes, RemoteAuthorization::default()).await;
        control.abort();
    }
    #[tokio::test]
    async fn immediate_regrant_cannot_hide_revocation_from_an_existing_stream() {
        let authorization = RemoteAuthorization {
            inbound: AuthorizationGrant {
                password: false,
                trusted_device: true,
            },
            outbound: AuthorizationGrant::password(true),
        };
        let publisher = AuthorizationPublisher::new(authorization);
        let live = publisher.live();
        let guard = live.guard(true, std::future::pending::<Result<()>>());
        tokio::pin!(guard);
        // Poll it once before doing two updates without yielding. A plain watch
        // would coalesce these to authorized=true and let the old work survive.
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut guard)
                .await
                .is_err()
        );
        publisher.send_modify(|a| a.inbound.trusted_device = false);
        publisher.send_modify(|a| a.inbound.trusted_device = true);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), &mut guard)
                .await
                .unwrap()
                .is_err()
        );
        assert!(publisher.live().guard(true, async { Ok(()) }).await.is_ok());
        assert!(live.guard(false, async { Ok(()) }).await.is_ok());
    }
}
