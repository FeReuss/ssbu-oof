//! DataStore objects posted by players (115/21 PostMetaBinary), changed (115/38 ChangeMeta) and read back by data ID or
//! persistence slot (115/8 GetMeta). Only the metadata is kept: no object payload is uploaded through this path. SSBU
//! keeps each player's online record in slot 0 (match data, disconnects, conduct warnings: docs/re/protocols.md), so
//! the store lives in SQLite (`database` in the config) and survives restarts. Data IDs are the table's row IDs.
//!
//! shortcut: one SQLite file per server; a deployment with several nodes needs a shared database instead.

use rusqlite::{Connection, OptionalExtension, Row, params};

/// Objects kept per owner; SSBU posts one per player (slot 0) and changes it afterwards.
const PER_OWNER: i64 = 64;

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
                 id INTEGER NOT NULL REFERENCES objects (id) ON DELETE CASCADE, PRIMARY KEY (owner, slot));",
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
        // The oldest objects beyond the bound go first (row IDs only grow).
        tx.execute(
            "DELETE FROM objects WHERE owner = ?1 AND id NOT IN \
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
        assert!(
            store.get(5, first, 0, 0).unwrap().is_none() && store.get(5, third, 0, 0).unwrap().is_none(),
            "oldest kept"
        );
        assert!(store.get(5, 0, 5, 7).unwrap().is_none(), "evicted object still in its slot");
        let n: i64 = store.db.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0)).unwrap();
        assert_eq!(n, PER_OWNER);
        let mine = store.post(&object(5, 0), Some((8, false))).unwrap();
        assert!(!store.change(6, 0, 5, 8, |o| o.meta_binary = vec![0]).unwrap(), "another player changed the object");
        assert!(store.change(5, 0, 5, 8, |o| o.meta_binary = vec![9]).unwrap());
        assert_eq!(store.get(6, mine, 0, 0).unwrap().unwrap().1.meta_binary, vec![9]);
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
