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
    use hbb_common::tokio;
    #[test]
    fn test_insert() {
        insert();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn insert() {
        let db = super::Database::new("test.sqlite3").await.unwrap();
        let mut jobs = vec![];
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                let empty_vec = Vec::new();
                cloned
                    .insert_peer(&id, &empty_vec, &empty_vec, "")
                    .await
                    .unwrap();
            });
            jobs.push(a);
        }
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                cloned.get_peer(&id).await.unwrap();
            });
            jobs.push(a);
        }
        hbb_common::futures::future::join_all(jobs).await;
    }
}
