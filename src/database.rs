use async_trait::async_trait;
use hbb_common::{log, ResultType};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteRow}, ConnectOptions, Connection, Error as SqlxError,
    Row, SqliteConnection,
};
use std::{ops::DerefMut, str::FromStr};
//use sqlx::postgres::PgPoolOptions;
//use sqlx::mysql::MySqlPoolOptions;

type Pool = deadpool::managed::Pool<DbPool>;

pub struct DbPool {
    url: String,
}

#[async_trait]
impl deadpool::managed::Manager for DbPool {
    type Type = SqliteConnection;
    type Error = SqlxError;
    async fn create(&self) -> Result<SqliteConnection, SqlxError> {
        let mut opt = SqliteConnectOptions::from_str(&self.url).unwrap();
        opt.log_statements(log::LevelFilter::Debug);
        SqliteConnection::connect_with(&opt).await
    }
    async fn recycle(
        &self,
        obj: &mut SqliteConnection,
    ) -> deadpool::managed::RecycleResult<SqlxError> {
        Ok(obj.ping().await?)
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool,
}

#[derive(Default)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
}

#[derive(Default, Clone)]
pub struct RegisteredPeer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
    pub note: Option<String>,
    pub created_at: Option<String>,
    pub management_policy: Option<String>,
}

impl Database {
    pub async fn new(url: &str) -> ResultType<Database> {
        if !std::path::Path::new(url).exists() {
            std::fs::File::create(url).ok();
        }
        let n: usize = std::env::var("MAX_DATABASE_CONNECTIONS")
            .unwrap_or_else(|_| "1".to_owned())
            .parse()
            .unwrap_or(1);
        log::debug!("MAX_DATABASE_CONNECTIONS={}", n);
        let pool = Pool::new(
            DbPool {
                url: url.to_owned(),
            },
            n,
        );
        let _ = pool.get().await?; // test
        let db = Database { pool };
        db.create_tables().await?;
        Ok(db)
    }

    async fn create_tables(&self) -> ResultType<()> {
        sqlx::query!(
            "
            create table if not exists peer (
                guid blob primary key not null,
                id varchar(100) not null,
                uuid blob not null,
                pk blob not null,
                created_at datetime not null default(current_timestamp),
                user blob,
                status tinyint,
                note varchar(300),
                management_policy text,
                info text not null
            ) without rowid;
            create unique index if not exists index_peer_id on peer (id);
            create index if not exists index_peer_user on peer (user);
            create index if not exists index_peer_created_at on peer (created_at);
            create index if not exists index_peer_status on peer (status);
        "
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        self.ensure_peer_management_columns().await;
        Ok(())
    }

    async fn ensure_peer_management_columns(&self) {
        let mut conn = match self.pool.get().await {
            Ok(conn) => conn,
            Err(err) => {
                log::error!("db migration connection failed: {}", err);
                return;
            }
        };
        let conn = conn.deref_mut();
        sqlx::query("alter table peer add column status tinyint")
            .execute(&mut *conn)
            .await
            .ok();
        sqlx::query("alter table peer add column note varchar(300)")
            .execute(&mut *conn)
            .await
            .ok();
        sqlx::query("alter table peer add column created_at datetime not null default(current_timestamp)")
            .execute(&mut *conn)
            .await
            .ok();
        sqlx::query("alter table peer add column management_policy text")
            .execute(&mut *conn)
            .await
            .ok();
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        Ok(sqlx::query_as!(
            Peer,
            "select guid, id, uuid, pk, user, status, info from peer where id = ?",
            id
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        sqlx::query!(
            "insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)",
            guid,
            id,
            uuid,
            pk,
            info
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(guid)
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        sqlx::query!(
            "update peer set id=?, pk=?, info=? where guid=?",
            id,
            pk,
            info,
            guid
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn list_registered_peers(
        &self,
        limit: usize,
        offset: usize,
    ) -> ResultType<Vec<RegisteredPeer>> {
        let mut conn = self.pool.get().await?;
        let rows = sqlx::query(
            "select guid, id, uuid, pk, user, status, note, management_policy, info, datetime(created_at) as created_at
             from peer
             order by created_at desc, id asc
             limit ? offset ?",
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(conn.deref_mut())
        .await?;
        Ok(rows.into_iter().map(registered_peer_from_row).collect())
    }

    pub async fn get_registered_peer(&self, id: &str) -> ResultType<Option<RegisteredPeer>> {
        let mut conn = self.pool.get().await?;
        let row = sqlx::query(
            "select guid, id, uuid, pk, user, status, note, management_policy, info, datetime(created_at) as created_at
             from peer
             where id = ?",
        )
        .bind(id)
        .fetch_optional(conn.deref_mut())
        .await?;
        Ok(row.map(registered_peer_from_row))
    }

    pub async fn set_peer_status(
        &self,
        id: &str,
        status: Option<i64>,
        note: Option<&str>,
    ) -> ResultType<bool> {
        let mut conn = self.pool.get().await?;
        let result = if let Some(status) = status {
            sqlx::query("update peer set status = ?, note = coalesce(?, note) where id = ?")
                .bind(status)
                .bind(note)
                .bind(id)
                .execute(conn.deref_mut())
                .await?
        } else {
            sqlx::query("update peer set status = null, note = coalesce(?, note) where id = ?")
                .bind(note)
                .bind(id)
                .execute(conn.deref_mut())
                .await?
        };
        Ok(result.rows_affected() > 0)
    }

    pub async fn set_peer_management_policy(
        &self,
        id: &str,
        management_policy: Option<&str>,
    ) -> ResultType<bool> {
        let mut conn = self.pool.get().await?;
        let result = sqlx::query("update peer set management_policy = ? where id = ?")
            .bind(management_policy)
            .bind(id)
            .execute(conn.deref_mut())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_registered_peer(&self, id: &str) -> ResultType<bool> {
        let mut conn = self.pool.get().await?;
        let result = sqlx::query("delete from peer where id = ?")
            .bind(id)
            .execute(conn.deref_mut())
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

fn registered_peer_from_row(row: SqliteRow) -> RegisteredPeer {
    RegisteredPeer {
        guid: row.try_get("guid").unwrap_or_default(),
        id: row.try_get("id").unwrap_or_default(),
        uuid: row.try_get("uuid").unwrap_or_default(),
        pk: row.try_get("pk").unwrap_or_default(),
        user: row.try_get("user").ok(),
        status: row.try_get("status").ok(),
        note: row.try_get("note").ok(),
        info: row.try_get("info").unwrap_or_default(),
        created_at: row.try_get("created_at").ok(),
        management_policy: row.try_get("management_policy").ok(),
    }
}

#[cfg(test)]
mod tests {
    //! Layer 1 (TDD): deterministic database CRUD roundtrip.
    //!
    //! Replaces the old `test_insert`, which raced 10 000 inserts into a fixed
    //! `test.sqlite3` with no assertions and no cleanup (non-deterministic under
    //! parallel `cargo test`, and it dirtied the working tree). This exercises
    //! the real Nemo-relevant columns (`status`, `management_policy`) against a
    //! self-migrated schema in a per-test temp database that is removed on drop.
    use super::*;
    use hbb_common::tokio;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// A sqlite file under the gitignored `target/` dir that deletes itself
    /// (and any sidecar journal/WAL files) when dropped, including on test
    /// panic. Two deliberate choices:
    /// - A *relative* path: `SqliteConnectOptions::from_str` mis-parses a
    ///   Windows absolute path (`C:\...`) as a URL scheme, so an absolute path
    ///   would fail to open.
    /// - Under `target/`: sqlx runs sqlite on a background thread and closes the
    ///   OS file handle slightly after this `Drop` returns, so on Windows the
    ///   unlink here can lose the race and leave the file behind. Keeping it in
    ///   the ignored build dir means a stray never dirties the git tree; the
    ///   unlink still succeeds on Linux/CI where handles close synchronously.
    struct TempDb(String);
    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let _ = std::fs::remove_file(format!("{}{}", self.0, suffix));
            }
        }
    }
    fn temp_db() -> TempDb {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let _ = std::fs::create_dir_all("target");
        TempDb(format!("target/nemo_test_{}_{}.sqlite3", std::process::id(), n))
    }

    #[test]
    fn peer_crud_roundtrip() {
        run_peer_crud_roundtrip();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn run_peer_crud_roundtrip() {
        let temp = temp_db();
        let db = Database::new(&temp.0).await.unwrap();

        let uuid = vec![1u8, 2, 3, 4];
        let pk = vec![9u8, 8, 7];
        db.insert_peer("ws-01", &uuid, &pk, "info-1").await.unwrap();

        // insert -> get roundtrip.
        let peer = db.get_peer("ws-01").await.unwrap().expect("peer should exist");
        assert_eq!(peer.id, "ws-01");
        assert_eq!(peer.uuid, uuid);
        assert_eq!(peer.pk, pk);

        // Absent peer reads as None, not an error.
        assert!(db.get_peer("does-not-exist").await.unwrap().is_none());

        // Status change is visible through the registered-peer view.
        assert!(db
            .set_peer_status("ws-01", Some(0), Some("blocked by test"))
            .await
            .unwrap());
        let reg = db.get_registered_peer("ws-01").await.unwrap().expect("registered");
        assert_eq!(reg.status, Some(0));
        assert_eq!(reg.note.as_deref(), Some("blocked by test"));

        // Management policy roundtrip on the Nemo column.
        let policy = r#"{"allow_user_override":false,"options":{"nemo-outbound-enabled":"N"}}"#;
        assert!(db
            .set_peer_management_policy("ws-01", Some(policy))
            .await
            .unwrap());
        let reg = db.get_registered_peer("ws-01").await.unwrap().expect("registered");
        assert_eq!(reg.management_policy.as_deref(), Some(policy));

        // Delete removes it; a second delete affects no rows.
        assert!(db.delete_registered_peer("ws-01").await.unwrap());
        assert!(db.get_registered_peer("ws-01").await.unwrap().is_none());
        assert!(!db.delete_registered_peer("ws-01").await.unwrap());
    }
}
