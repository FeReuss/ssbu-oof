//! DataStore objects posted by players (115/21 PostMetaBinary, 115/24 PreparePostObject), changed (115/38 ChangeMeta)
//! and read back by data ID or persistence slot (115/8 GetMeta). Objects prepared with 24 get their payload over HTTP
//! (`/v1/objects/<id>`, shared content such as replays) and become readable once the poster completes them (115/26).
//! SSBU keeps each player's online record in slot 0 (match data, disconnects, conduct warnings: docs/re/protocols.md),
//! so the store lives in SQLite (`database` in the config) and survives restarts. Data IDs are the table's row IDs.
//!
//! shortcut: one SQLite file per server; a deployment with several nodes needs a shared database instead.

use rusqlite::{Connection, OptionalExtension, Row, params};

/// Objects kept per owner; SSBU posts one per player (slot 0) and changes it afterwards.
const PER_OWNER: i64 = 64;
/// Largest payload accepted (a replay is ~0.5 MB; videos are the largest shared content).
pub const MAX_PAYLOAD: usize = 64 << 20;

/// NEX `DataStorePermission`: who may read (or delete) an object.
#[derive(Debug, Clone, PartialEq)]
pub struct Permission {
    pub kind: u8,
    pub recipients: Vec<u64>,
}

impl Permission {
    /// 0 public, 2 the listed PIDs, 3 private; the owner always. Friend-based kinds (1, 4) admit only the listed PIDs
    /// until the server knows friend lists.
    pub fn allows(&self, owner: u64, pid: u64) -> bool {
        pid == owner || self.kind == 0 || (self.kind != 3 && self.recipients.contains(&pid))
    }

    fn column(&self) -> String {
        std::iter::once(self.kind.to_string())
            .chain(self.recipients.iter().map(u64::to_string))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn parse(text: &str) -> Self {
        let mut parts = text.split(',').filter_map(|p| p.parse::<u64>().ok());
        Permission { kind: parts.next().unwrap_or(3) as u8, recipients: parts.collect() }
    }
}

#[derive(Debug, Clone)]
pub struct Object {
    pub owner: u64,
    pub size: u32,
    pub name: String,
    pub data_type: u16,
    pub meta_binary: Vec<u8>,
    pub permission: Permission,
    pub delete_permission: Permission,
    /// NEX DateTimes of the post and of the last change.
    pub created: u64,
    pub updated: u64,
    pub period: u16,
    pub refer_data_id: u32,
    pub flag: u32,
    pub tags: Vec<String>,
}

const COLUMNS: &str = "owner, size, name, data_type, meta_binary, permission, delete_permission, created, updated, \
                       period, refer_data_id, flag, tags";

impl Object {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(Object {
            owner: r.get::<_, i64>(0)? as u64,
            size: r.get(1)?,
            name: r.get(2)?,
            data_type: r.get(3)?,
            meta_binary: r.get(4)?,
            permission: Permission::parse(&r.get::<_, String>(5)?),
            delete_permission: Permission::parse(&r.get::<_, String>(6)?),
            created: r.get::<_, i64>(7)? as u64,
            updated: r.get::<_, i64>(8)? as u64,
            period: r.get(9)?,
            refer_data_id: r.get(10)?,
            flag: r.get(11)?,
            tags: serde_json::from_str(&r.get::<_, String>(12)?).unwrap_or_default(),
        })
    }
}

/// Signature in an object's upload (`put`) or download URL (`?k=`): HMAC-SHA256 of the data ID under the server
/// secret, 128 bits as hex.
pub fn url_key(secret: &[u8], id: u64, put: bool) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let mut m = Hmac::<sha2::Sha256>::new_from_slice(secret).expect("HMAC takes any key size");
    m.update(if put { b"object-put" } else { b"object-get" });
    m.update(&id.to_le_bytes());
    m.finalize().into_bytes()[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// The file in a `multipart/form-data` body (the part named "file", as a presigned S3 POST sends it), or the whole
/// body for any other content type.
pub fn upload_body<'a>(content_type: &str, body: &'a [u8]) -> Option<&'a [u8]> {
    let Some(boundary) = content_type.strip_prefix("multipart/form-data").and_then(|r| r.split("boundary=").nth(1))
    else {
        return Some(body);
    };
    let delimiter = format!("\r\n--{}", boundary.trim_matches('"'));
    let mut rest = body.strip_prefix(&delimiter.as_bytes()[2..])?;
    loop {
        let end = rest.windows(delimiter.len()).position(|w| w == delimiter.as_bytes())?;
        let (part, next) = rest.split_at(end);
        let split = part.windows(4).position(|w| w == b"\r\n\r\n")?;
        let headers = String::from_utf8_lossy(&part[..split]);
        if headers.contains("name=\"file\"") {
            return Some(&part[split + 4..]);
        }
        rest = &next[delimiter.len()..];
    }
}

/// One Shared Content entry.
pub struct Shared {
    pub id: u64,
    pub object: Object,
    /// The game's share description (115/62), as sent.
    pub info: Vec<u8>,
    pub likes: u32,
}

pub struct ObjectStore {
    db: Connection,
}

impl ObjectStore {
    /// `path` = None: an in-memory database (tests, throwaway servers).
    pub fn open(path: Option<&str>) -> rusqlite::Result<Self> {
        let db = match path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        db.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS objects (id INTEGER PRIMARY KEY, owner INTEGER NOT NULL, size INTEGER NOT NULL,
                 name TEXT NOT NULL, data_type INTEGER NOT NULL, meta_binary BLOB NOT NULL, permission TEXT NOT NULL,
                 delete_permission TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL,
                 period INTEGER NOT NULL, refer_data_id INTEGER NOT NULL, flag INTEGER NOT NULL, tags TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS objects_owner ON objects (owner);
             CREATE TABLE IF NOT EXISTS slots (owner INTEGER NOT NULL, slot INTEGER NOT NULL,
                 id INTEGER NOT NULL REFERENCES objects (id) ON DELETE CASCADE, PRIMARY KEY (owner, slot));
             CREATE TABLE IF NOT EXISTS payloads (id INTEGER PRIMARY KEY REFERENCES objects (id) ON DELETE CASCADE,
                 data BLOB NOT NULL, complete INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS shares (id INTEGER PRIMARY KEY REFERENCES objects (id) ON DELETE CASCADE,
                 kind INTEGER NOT NULL, info BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS likes (id INTEGER NOT NULL REFERENCES shares (id) ON DELETE CASCADE,
                 pid INTEGER NOT NULL, PRIMARY KEY (id, pid));",
        )?;
        Ok(ObjectStore { db })
    }

    /// Store `object`; `slot` = (persistence slot, delete the object it held before). Returns its data ID.
    pub fn post(&mut self, object: &Object, slot: Option<(u16, bool)>) -> rusqlite::Result<u64> {
        let tx = self.db.transaction()?;
        tx.execute(
            &format!("INSERT INTO objects ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"),
            params![
                object.owner as i64,
                object.size,
                object.name,
                object.data_type,
                object.meta_binary,
                object.permission.column(),
                object.delete_permission.column(),
                object.created as i64,
                object.updated as i64,
                object.period,
                object.refer_data_id,
                object.flag,
                serde_json::to_string(&object.tags).expect("tags"),
            ],
        )?;
        let id = tx.last_insert_rowid();
        let owner = object.owner as i64;
        if let Some((slot, delete_last)) = slot {
            let old: Option<i64> = tx
                .query_row("SELECT id FROM slots WHERE owner = ?1 AND slot = ?2", params![owner, slot], |r| r.get(0))
                .optional()?;
            tx.execute("INSERT OR REPLACE INTO slots (owner, slot, id) VALUES (?1, ?2, ?3)", params![owner, slot, id])?;
            if let (Some(old), true) = (old, delete_last) {
                tx.execute("DELETE FROM objects WHERE id = ?1", [old])?;
            }
        }
        // The oldest objects beyond the bound go first (row IDs only grow); objects in a persistence slot (the player's
        // online record) are never evicted.
        tx.execute(
            "DELETE FROM objects WHERE owner = ?1 AND id NOT IN (SELECT id FROM slots) AND id NOT IN \
             (SELECT id FROM objects WHERE owner = ?1 ORDER BY id DESC LIMIT ?2)",
            params![owner, PER_OWNER],
        )?;
        tx.commit()?;
        Ok(id as u64)
    }

    fn id(&self, data_id: u64, owner: u64, slot: u16) -> rusqlite::Result<Option<i64>> {
        if data_id != 0 {
            return Ok(Some(data_id as i64));
        }
        self.db
            .query_row("SELECT id FROM slots WHERE owner = ?1 AND slot = ?2", params![owner as i64, slot], |r| r.get(0))
            .optional()
    }

    fn load(&self, id: i64) -> rusqlite::Result<Option<Object>> {
        self.db.query_row(&format!("SELECT {COLUMNS} FROM objects WHERE id = ?1"), [id], Object::from_row).optional()
    }

    /// The object `pid` may read: by data ID, or (data ID 0) the one in the owner's persistence slot.
    pub fn get(&self, pid: u64, data_id: u64, owner: u64, slot: u16) -> rusqlite::Result<Option<(u64, Object)>> {
        let Some(id) = self.id(data_id, owner, slot)? else { return Ok(None) };
        Ok(self.load(id)?.filter(|o| o.permission.allows(o.owner, pid)).map(|o| (id as u64, o)))
    }

    /// Stores the payload of a prepared object; false for an unknown object or a size other than the one declared.
    pub fn upload(&mut self, id: u64, data: &[u8]) -> rusqlite::Result<bool> {
        let size: Option<u32> =
            self.db.query_row("SELECT size FROM objects WHERE id = ?1", [id as i64], |r| r.get(0)).optional()?;
        if size != Some(data.len() as u32) || data.len() > MAX_PAYLOAD {
            return Ok(false);
        }
        self.db.execute(
            "INSERT OR REPLACE INTO payloads (id, data, complete) VALUES (?1, ?2, 0)",
            params![id as i64, data],
        )?;
        Ok(true)
    }

    /// CompletePostObject by the owner: a successful post with its payload uploaded becomes readable, a failed one is
    /// deleted. False when `pid` has no such object or its payload never arrived.
    pub fn complete(&mut self, pid: u64, id: u64, success: bool) -> rusqlite::Result<bool> {
        if !self.load(id as i64)?.is_some_and(|o| o.owner == pid) {
            return Ok(false);
        }
        if !success {
            self.db.execute("DELETE FROM objects WHERE id = ?1", [id as i64])?;
            return Ok(true);
        }
        Ok(self.db.execute("UPDATE payloads SET complete = 1 WHERE id = ?1", [id as i64])? == 1)
    }

    /// The completed payload of object `id`.
    pub fn payload(&self, id: u64) -> rusqlite::Result<Option<Vec<u8>>> {
        self.db
            .query_row("SELECT data FROM payloads WHERE id = ?1 AND complete = 1", [id as i64], |r| r.get(0))
            .optional()
    }

    /// Lists a completed object of `pid` in Shared Content with the game's share description (115/62).
    pub fn share(&mut self, pid: u64, id: u64, kind: u8, info: &[u8]) -> rusqlite::Result<bool> {
        if !self.load(id as i64)?.is_some_and(|o| o.owner == pid) || self.payload(id)?.is_none() {
            return Ok(false);
        }
        self.db.execute(
            "INSERT OR REPLACE INTO shares (id, kind, info) VALUES (?1, ?2, ?3)",
            params![id as i64, kind, info],
        )?;
        Ok(true)
    }

    /// Shared Content of one DataStore data type (None: every type, most liked first), else newest first.
    pub fn shared(&self, data_type: Option<u16>, offset: u32, limit: u32) -> rusqlite::Result<Vec<Shared>> {
        let mut q = self.db.prepare(&format!(
            "SELECT {COLUMNS}, s.id, s.info, (SELECT COUNT(*) FROM likes l WHERE l.id = s.id) AS n \
             FROM shares s JOIN objects o ON o.id = s.id WHERE ?3 IS NULL OR o.data_type = ?3 \
             ORDER BY CASE WHEN ?3 IS NULL THEN n ELSE 0 END DESC, s.id DESC LIMIT ?1 OFFSET ?2"
        ))?;
        let rows = q.query_map(params![limit, offset, data_type], |r| {
            Ok(Shared {
                id: r.get::<_, i64>(13)? as u64,
                object: Object::from_row(r)?,
                info: r.get(14)?,
                likes: r.get(15)?,
            })
        })?;
        rows.collect()
    }

    /// A player's like on shared content, given or taken back (an unknown or unshared ID is ignored).
    pub fn like(&mut self, id: u64, pid: u64, on: bool) -> rusqlite::Result<()> {
        let sql = if on {
            "INSERT OR IGNORE INTO likes (id, pid) SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM shares WHERE id = ?1)"
        } else {
            "DELETE FROM likes WHERE id = ?1 AND pid = ?2"
        };
        self.db.execute(sql, params![id as i64, pid as i64])?;
        Ok(())
    }

    /// The same lookup for a change, which only the owner may make; false when `pid` has no such object.
    pub fn change(
        &mut self,
        pid: u64,
        data_id: u64,
        owner: u64,
        slot: u16,
        edit: impl FnOnce(&mut Object),
    ) -> rusqlite::Result<bool> {
        let Some(id) = self.id(data_id, owner, slot)? else { return Ok(false) };
        let Some(mut o) = self.load(id)?.filter(|o| o.owner == pid) else { return Ok(false) };
        edit(&mut o);
        self.db.execute(
            "UPDATE objects SET name = ?2, data_type = ?3, meta_binary = ?4, permission = ?5, delete_permission = ?6,
                 updated = ?7, period = ?8, tags = ?9 WHERE id = ?1",
            params![
                id,
                o.name,
                o.data_type,
                o.meta_binary,
                o.permission.column(),
                o.delete_permission.column(),
                o.updated as i64,
                o.period,
                serde_json::to_string(&o.tags).expect("tags"),
            ],
        )?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(owner: u64, kind: u8) -> Object {
        Object {
            owner,
            size: 0,
            name: String::new(),
            data_type: 0,
            meta_binary: vec![1, 2, 3],
            permission: Permission { kind, recipients: vec![9] },
            delete_permission: Permission { kind: 3, recipients: vec![] },
            created: 0,
            updated: 0,
            period: 90,
            refer_data_id: 0,
            flag: 0,
            tags: vec!["t".into()],
        }
    }

    #[test]
    fn permissions_slots_and_the_per_owner_bound() {
        let mut store = ObjectStore::open(None).unwrap();
        let first = store.post(&object(5, 3), None).unwrap();
        assert!(store.get(5, first, 0, 0).unwrap().is_some());
        assert!(store.get(6, first, 0, 0).unwrap().is_none(), "private object visible to another player");
        let second = store.post(&object(5, 2), Some((7, false))).unwrap();
        assert_eq!(store.get(9, 0, 5, 7).unwrap().map(|(id, _)| id), Some(second), "recipient reads the slot");
        assert!(store.get(6, second, 0, 0).unwrap().is_none());
        let third = store.post(&object(5, 0), Some((7, true))).unwrap();
        assert!(store.get(5, second, 0, 0).unwrap().is_none(), "replaced slot object kept");
        assert_eq!(store.get(6, 0, 5, 7).unwrap().map(|(id, o)| (id, o.tags)), Some((third, vec!["t".to_string()])));
        for _ in 0..PER_OWNER {
            store.post(&object(5, 0), None).unwrap();
        }
        assert!(store.get(5, first, 0, 0).unwrap().is_none(), "oldest kept");
        assert_eq!(store.get(5, 0, 5, 7).unwrap().map(|(id, _)| id), Some(third), "slot object evicted");
        let n: i64 = store.db.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0)).unwrap();
        assert_eq!(n, PER_OWNER + 1, "the bound plus the slot object");
        let mine = store.post(&object(5, 0), Some((8, false))).unwrap();
        assert!(!store.change(6, 0, 5, 8, |o| o.meta_binary = vec![0]).unwrap(), "another player changed the object");
        assert!(store.change(5, 0, 5, 8, |o| o.meta_binary = vec![9]).unwrap());
        assert_eq!(store.get(6, mine, 0, 0).unwrap().unwrap().1.meta_binary, vec![9]);
    }

    #[test]
    fn payloads_upload_complete_and_slots_survive_the_bound() {
        let mut store = ObjectStore::open(None).unwrap();
        let record = store.post(&object(5, 3), Some((0, true))).unwrap();
        let mut replay = object(5, 0);
        replay.size = 3;
        let id = store.post(&replay, None).unwrap();
        assert!(!store.upload(id, &[1, 2]).unwrap(), "size other than the declared one");
        assert!(store.upload(id, &[1, 2, 3]).unwrap());
        assert_eq!(store.payload(id).unwrap(), None, "readable before CompletePostObject");
        assert!(!store.complete(6, id, true).unwrap(), "completed by another player");
        assert!(store.complete(5, id, true).unwrap());
        assert_eq!(store.payload(id).unwrap(), Some(vec![1, 2, 3]));
        assert!(!store.share(6, id, 3, b"x").unwrap(), "shared by another player");
        assert!(store.share(5, id, 3, b"info").unwrap());
        assert!(store.shared(Some(1), 0, 10).unwrap().is_empty(), "another data type listed");
        store.like(id, 7, true).unwrap();
        store.like(id, 7, true).unwrap();
        store.like(id, 8, true).unwrap();
        store.like(id, 8, false).unwrap();
        store.like(999, 7, true).unwrap(); // never shared: ignored
        let listed: Vec<_> =
            store.shared(Some(0), 0, 10).unwrap().into_iter().map(|s| (s.id, s.info, s.likes)).collect();
        assert_eq!(listed, vec![(id, b"info".to_vec(), 1)], "one like per player");
        let failed = store.post(&replay, None).unwrap();
        assert!(store.complete(5, failed, false).unwrap());
        assert!(store.get(5, failed, 0, 0).unwrap().is_none(), "failed post kept");
        for _ in 0..PER_OWNER {
            store.post(&object(5, 0), None).unwrap();
        }
        assert!(store.get(5, record, 0, 0).unwrap().is_some(), "the slot-0 record was evicted");
        assert_eq!(store.payload(id).unwrap(), None, "payload outlived its evicted object");
    }

    #[test]
    fn upload_bodies() {
        assert_eq!(upload_body("application/octet-stream", b"abc"), Some(&b"abc"[..]));
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nv\r\n--XyZ\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"f\"\r\nContent-Type: application/octet-stream\r\n\r\n\x01\r\n\x02\r\n--XyZ--\r\n";
        assert_eq!(upload_body("multipart/form-data; boundary=XyZ", body), Some(&b"\x01\r\n\x02"[..]));
        assert_eq!(upload_body("multipart/form-data; boundary=Other", body), None);
        assert_ne!(url_key(b"s", 1, true), url_key(b"s", 1, false));
    }

    #[test]
    fn objects_survive_a_restart() {
        let path = std::env::temp_dir().join(format!("oof-objects-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let id = {
            let mut store = ObjectStore::open(path.to_str()).unwrap();
            let id = store.post(&object(5, 0), Some((0, true))).unwrap();
            assert!(store.change(5, id, 0, 0, |o| o.meta_binary = vec![4]).unwrap());
            id
        };
        let store = ObjectStore::open(path.to_str()).unwrap();
        assert_eq!(store.get(5, 0, 5, 0).unwrap().map(|(i, o)| (i, o.meta_binary)), Some((id, vec![4])));
        drop(store);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
