//! Stable public device addresses. These numbers never authenticate a device.
use crate::{
    error::{Error, Result},
    identity::NodeId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const FIRST_SHORT_ID: u32 = 100_000_000;
pub const LAST_SHORT_ID: u32 = 999_999_999;
const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
pub struct ShortId(u32);
impl<'de> Deserialize<'de> for ShortId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = u32::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}
impl ShortId {
    pub fn new(value: u32) -> Result<Self> {
        if !(FIRST_SHORT_ID..=LAST_SHORT_ID).contains(&value) {
            return Err(Error::Discovery(
                "设备 ID 必须是 100000000..999999999 的 9 位数字".into(),
            ));
        }
        Ok(Self(value))
    }
    pub fn normalize(input: &str) -> Result<Self> {
        // Only ASCII spaces/hyphens are presentation separators; no Unicode digits.
        if input.len() > 32
            || input
                .bytes()
                .any(|b| !b.is_ascii_digit() && b != b' ' && b != b'-')
        {
            return Err(Error::Discovery("设备 ID 格式无效".into()));
        }
        let digits: String = input
            .chars()
            .filter(|ch| *ch != ' ' && *ch != '-')
            .collect();
        if digits.len() != 9 {
            return Err(Error::Discovery("设备 ID 必须是 9 位数字".into()));
        }
        Self::new(
            digits
                .parse()
                .map_err(|_| Error::Discovery("设备 ID 格式无效".into()))?,
        )
    }
    pub fn value(self) -> u32 {
        self.0
    }
    pub fn display(self) -> String {
        let s = self.0.to_string();
        format!("{} {} {}", &s[..3], &s[3..6], &s[6..])
    }
}
impl fmt::Display for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
fn db_error(error: impl fmt::Display) -> Error {
    Error::Discovery(format!("短设备 ID SQLite：{error}"))
}

/// Each connection serializes local use; BEGIN IMMEDIATE also protects independent
/// processes/connections sharing the same file. Never derive numbers from MAX().
pub struct ShortIdStore {
    connection: Mutex<Connection>,
}
impl ShortIdStore {
    pub fn open(path: Option<&Path>) -> Result<Self> {
        let mut connection = match path {
            Some(path) => Connection::open(path),
            None => Connection::open_in_memory(),
        }
        .map_err(db_error)?;
        connection
            .busy_timeout(Duration::from_secs(2))
            .map_err(db_error)?;
        connection
            .pragma_update(None, "foreign_keys", true)
            .map_err(db_error)?;
        let migration = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let version: u32 = migration
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(db_error)?;
        if version > SCHEMA_VERSION {
            return Err(db_error("不支持的 schema version"));
        }
        if version == 0 {
            migration.execute_batch("CREATE TABLE device_id_mapping (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_identity TEXT NOT NULL UNIQUE,
                short_id INTEGER NOT NULL UNIQUE CHECK(short_id BETWEEN 100000000 AND 999999999),
                created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL
            );
            CREATE TABLE short_id_sequence (id INTEGER PRIMARY KEY CHECK(id=1), next_id INTEGER NOT NULL CHECK(next_id BETWEEN 100000000 AND 1000000000));
            INSERT INTO short_id_sequence(id,next_id) VALUES(1,100000000);
            PRAGMA user_version=1;").map_err(db_error)?;
        }
        migration.commit().map_err(db_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }
    pub fn register(&self, identity: NodeId) -> Result<ShortId> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| db_error("数据库锁已损坏"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(db_error)?
            .as_secs() as i64;
        let identity = identity.to_hex();
        if let Some(id) = transaction
            .query_row(
                "SELECT short_id FROM device_id_mapping WHERE device_identity=?1",
                [&identity],
                |row| row.get::<_, u32>(0),
            )
            .optional()
            .map_err(db_error)?
        {
            transaction
                .execute(
                    "UPDATE device_id_mapping SET last_seen_at=?1 WHERE device_identity=?2",
                    params![now, identity],
                )
                .map_err(db_error)?;
            transaction.commit().map_err(db_error)?;
            return ShortId::new(id);
        }
        let next: u32 = transaction
            .query_row(
                "SELECT next_id FROM short_id_sequence WHERE id=1",
                [],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if next > LAST_SHORT_ID {
            return Err(db_error("9 位设备 ID 号池已耗尽"));
        }
        let id = ShortId::new(next)?;
        transaction.execute("INSERT INTO device_id_mapping(device_identity,short_id,created_at,last_seen_at) VALUES(?1,?2,?3,?3)", params![identity,next,now]).map_err(db_error)?;
        transaction
            .execute(
                "UPDATE short_id_sequence SET next_id=?1 WHERE id=1",
                [next + 1],
            )
            .map_err(db_error)?;
        transaction.commit().map_err(db_error)?;
        Ok(id)
    }
    pub fn lookup(&self, id: ShortId) -> Result<Option<NodeId>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| db_error("数据库锁已损坏"))?;
        let identity: Option<String> = connection
            .query_row(
                "SELECT device_identity FROM device_id_mapping WHERE short_id=?1",
                [id.value()],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?;
        identity
            .map(|identity| NodeId::from_hex(&identity))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("p2p-short-{}.sqlite3", rand::random::<u128>()))
    }
    #[test]
    fn mapping_write_failure_rolls_back_sequence_and_timestamps_update_only_on_register() {
        let store = ShortIdStore::open(None).unwrap();
        let identity = Identity::generate().node_id();
        store.connection.lock().unwrap().execute_batch("CREATE TRIGGER fail_mapping BEFORE INSERT ON device_id_mapping BEGIN SELECT RAISE(ABORT,'injected mapping failure'); END;").unwrap();
        assert!(store.register(identity).is_err());
        let db = store.connection.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT next_id FROM short_id_sequence", [], |r| r
                .get::<_, u32>(0))
                .unwrap(),
            FIRST_SHORT_ID
        );
        db.execute_batch("DROP TRIGGER fail_mapping").unwrap();
        drop(db);
        let id = store.register(identity).unwrap();
        let created = store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT created_at FROM device_id_mapping", [], |r| {
                r.get::<_, u64>(0)
            })
            .unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch("UPDATE device_id_mapping SET last_seen_at=0")
            .unwrap();
        assert_eq!(store.lookup(id).unwrap(), Some(identity));
        assert_eq!(store.register(identity).unwrap(), id);
        let db = store.connection.lock().unwrap();
        let (first, last) = db
            .query_row(
                "SELECT created_at,last_seen_at FROM device_id_mapping",
                [],
                |r| Ok((r.get::<_, u64>(0)?, r.get::<_, u64>(1)?)),
            )
            .unwrap();
        assert_eq!(first, created);
        assert!(last > 0);
        assert!(db.execute("INSERT INTO device_id_mapping(device_identity,short_id,created_at,last_seen_at) VALUES(?1,?2,0,0)",params![identity.to_hex(),FIRST_SHORT_ID+1]).is_err());
        assert!(db.execute("INSERT INTO device_id_mapping(device_identity,short_id,created_at,last_seen_at) VALUES(?1,?2,0,0)",params![Identity::generate().node_id().to_hex(),FIRST_SHORT_ID]).is_err());
        assert!(postcard::from_bytes::<ShortId>(&postcard::to_allocvec(&1u32).unwrap()).is_err());
    }
    #[test]
    fn normalization_and_range_are_strict() {
        for text in ["100000123", "100 000 123", "100-000-123"] {
            assert_eq!(ShortId::normalize(text).unwrap().value(), 100000123);
        }
        for text in [
            "099999999",
            "1000000000",
            "９００００００００",
            "100\t000123",
            "100_000_123",
            "",
            "abc000123",
        ] {
            assert!(ShortId::normalize(text).is_err(), "{text}");
        }
    }
    #[test]
    fn sequential_stable_and_persistent() {
        let path = path();
        let a = Identity::generate().node_id();
        let b = Identity::generate().node_id();
        let store = ShortIdStore::open(Some(&path)).unwrap();
        assert_eq!(store.register(a).unwrap().value(), FIRST_SHORT_ID);
        assert_eq!(store.register(b).unwrap().value(), FIRST_SHORT_ID + 1);
        assert_eq!(store.register(a).unwrap().value(), FIRST_SHORT_ID);
        drop(store);
        let reopened = ShortIdStore::open(Some(&path)).unwrap();
        assert_eq!(reopened.register(a).unwrap().value(), FIRST_SHORT_ID);
        assert_eq!(
            reopened
                .lookup(ShortId::new(FIRST_SHORT_ID + 1).unwrap())
                .unwrap(),
            Some(b)
        );
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn independent_connections_atomically_allocate_and_deduplicate() {
        let path = path();
        drop(ShortIdStore::open(Some(&path)).unwrap());
        let shared = Identity::generate().node_id();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let store = ShortIdStore::open(Some(&path)).unwrap();
                    barrier.wait();
                    store
                        .register(if i < 8 {
                            shared
                        } else {
                            Identity::generate().node_id()
                        })
                        .unwrap()
                        .value()
                })
            })
            .collect();
        let ids: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(ids[..8].iter().all(|id| *id == ids[0]));
        let unique: std::collections::BTreeSet<_> = ids.into_iter().collect();
        assert_eq!(
            unique.into_iter().collect::<Vec<_>>(),
            (FIRST_SHORT_ID..FIRST_SHORT_ID + 9).collect::<Vec<_>>()
        );
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn rollback_exhaustion_corruption_and_future_schema() {
        let store = ShortIdStore::open(None).unwrap();
        {
            let db = store.connection.lock().unwrap();
            db.execute_batch("CREATE TRIGGER fail_sequence BEFORE UPDATE ON short_id_sequence BEGIN SELECT RAISE(ABORT,'injected sequence failure'); END;").unwrap();
        }
        assert!(
            store
                .register(Identity::generate().node_id())
                .unwrap_err()
                .to_string()
                .contains("injected sequence failure")
        );
        {
            let db = store.connection.lock().unwrap();
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM device_id_mapping", [], |r| r
                    .get::<_, u32>(0))
                    .unwrap(),
                0
            );
            db.execute_batch(
                "DROP TRIGGER fail_sequence; UPDATE short_id_sequence SET next_id=999999999;",
            )
            .unwrap();
        }
        assert_eq!(
            store
                .register(Identity::generate().node_id())
                .unwrap()
                .value(),
            LAST_SHORT_ID
        );
        assert!(
            store
                .register(Identity::generate().node_id())
                .unwrap_err()
                .to_string()
                .contains("耗尽")
        );
        let p = path();
        std::fs::write(&p, b"corrupt sqlite").unwrap();
        assert!(ShortIdStore::open(Some(&p)).is_err());
        std::fs::remove_file(&p).unwrap();
        let db = Connection::open(&p).unwrap();
        db.pragma_update(None, "user_version", 99).unwrap();
        drop(db);
        assert!(ShortIdStore::open(Some(&p)).is_err());
        std::fs::remove_file(p).unwrap();
    }
    #[test]
    fn locked_database_returns_real_error_without_allocating() {
        let p = path();
        let store = ShortIdStore::open(Some(&p)).unwrap();
        let other = Connection::open(&p).unwrap();
        other.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(
            store
                .register(Identity::generate().node_id())
                .unwrap_err()
                .to_string()
                .contains("locked")
        );
        other.execute_batch("ROLLBACK").unwrap();
        assert_eq!(
            store
                .register(Identity::generate().node_id())
                .unwrap()
                .value(),
            FIRST_SHORT_ID
        );
        drop((store, other));
        std::fs::remove_file(p).unwrap();
    }
}
