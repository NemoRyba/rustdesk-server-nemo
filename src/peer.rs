use crate::common::*;
use crate::database;
use hbb_common::{
    bytes::Bytes,
    log,
    rendezvous_proto::*,
    tokio::sync::{Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, collections::HashSet, net::SocketAddr, sync::Arc, time::Instant};

type IpBlockMap = HashMap<String, ((u32, Instant), (HashSet<String>, Instant))>;
type UserStatusMap = HashMap<Vec<u8>, Arc<(Option<Vec<u8>>, bool)>>;
type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref USER_STATUS: RwLock<UserStatusMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub const IP_CHANGE_DUR: u64 = 180;
pub const IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub const DAY_SECONDS: u64 = 3600 * 24;
pub const IP_BLOCK_DUR: u64 = 60;
pub const PEER_ONLINE_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
}

pub(crate) struct Peer {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) last_reg_time: Instant,
    pub(crate) guid: Vec<u8>,
    pub(crate) uuid: Bytes,
    pub(crate) pk: Bytes,
    // pub(crate) user: Option<Vec<u8>>,
    pub(crate) info: PeerInfo,
    pub(crate) status: Option<i64>,
    pub(crate) reg_pk: (u32, Instant), // how often register_pk
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            last_reg_time: get_expired_time(),
            guid: Vec::new(),
            uuid: Bytes::new(),
            pk: Bytes::new(),
            info: Default::default(),
            // user: None,
            status: None,
            reg_pk: (0, get_expired_time()),
        }
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

#[derive(Clone, Debug, Default)]
pub(crate) struct PeerRuntimeSnapshot {
    pub(crate) public_addr: Option<String>,
    pub(crate) last_seen_ms_ago: Option<u64>,
    pub(crate) online: bool,
    pub(crate) registered_ip: Option<String>,
    pub(crate) status: Option<i64>,
}

#[derive(Clone)]
pub(crate) struct PeerMap {
    map: Arc<RwLock<HashMap<String, LockPeer>>>,
    pub(crate) db: database::Database,
}

impl PeerMap {
    pub(crate) async fn new() -> ResultType<Self> {
        let db = std::env::var("DB_URL").unwrap_or({
            let mut db = "db_v2.sqlite3".to_owned();
            #[cfg(all(windows, not(debug_assertions)))]
            {
                if let Some(path) = hbb_common::config::Config::icon_path().parent() {
                    db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
                }
            }
            #[cfg(not(windows))]
            {
                db = format!("./{db}");
            }
            db
        });
        log::info!("DB_URL={}", db);
        let pm = Self {
            map: Default::default(),
            db: database::Database::new(&db).await?,
        };
        Ok(pm)
    }

    #[inline]
    pub(crate) async fn update_pk(
        &mut self,
        id: String,
        peer: LockPeer,
        addr: SocketAddr,
        uuid: Bytes,
        pk: Bytes,
        ip: String,
    ) -> register_pk_response::Result {
        log::info!("update_pk {} {:?} {:?} {:?}", id, addr, uuid, pk);
        let (info_str, guid) = {
            let mut w = peer.write().await;
            w.socket_addr = addr;
            w.uuid = uuid.clone();
            w.pk = pk.clone();
            w.last_reg_time = Instant::now();
            w.info.ip = ip;
            (
                serde_json::to_string(&w.info).unwrap_or_default(),
                w.guid.clone(),
            )
        };
        if guid.is_empty() {
            match self.db.insert_peer(&id, &uuid, &pk, &info_str).await {
                Err(err) => {
                    log::error!("db.insert_peer failed: {}", err);
                    return register_pk_response::Result::SERVER_ERROR;
                }
                Ok(guid) => {
                    peer.write().await.guid = guid;
                }
            }
        } else {
            if let Err(err) = self.db.update_pk(&guid, &id, &pk, &info_str).await {
                log::error!("db.update_pk failed: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
            log::info!("pk updated instead of insert");
        }
        register_pk_response::Result::OK
    }

    #[inline]
    pub(crate) async fn get(&self, id: &str) -> Option<LockPeer> {
        let p = self.map.read().await.get(id).cloned();
        if p.is_some() {
            return p;
        } else if let Ok(Some(v)) = self.db.get_peer(id).await {
            let peer = Peer {
                guid: v.guid,
                uuid: v.uuid.into(),
                pk: v.pk.into(),
                // user: v.user,
                info: serde_json::from_str::<PeerInfo>(&v.info).unwrap_or_default(),
                status: v.status,
                ..Default::default()
            };
            let peer = Arc::new(RwLock::new(peer));
            self.map.write().await.insert(id.to_owned(), peer.clone());
            return Some(peer);
        }
        None
    }

    #[inline]
    pub(crate) async fn get_or(&self, id: &str) -> LockPeer {
        if let Some(p) = self.get(id).await {
            return p;
        }
        let mut w = self.map.write().await;
        if let Some(p) = w.get(id) {
            return p.clone();
        }
        let tmp = LockPeer::default();
        w.insert(id.to_owned(), tmp.clone());
        tmp
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        self.map.read().await.get(id).cloned()
    }

    #[inline]
    pub(crate) async fn is_in_memory(&self, id: &str) -> bool {
        self.map.read().await.contains_key(id)
    }

    pub(crate) async fn get_registered(
        &self,
        id: &str,
    ) -> ResultType<Option<database::RegisteredPeer>> {
        self.db.get_registered_peer(id).await
    }

    pub(crate) async fn list_registered(
        &self,
        limit: usize,
        offset: usize,
    ) -> ResultType<Vec<database::RegisteredPeer>> {
        self.db.list_registered_peers(limit, offset).await
    }

    pub(crate) async fn set_peer_status(
        &self,
        id: &str,
        status: Option<i64>,
        note: Option<&str>,
    ) -> ResultType<bool> {
        let updated = self.db.set_peer_status(id, status, note).await?;
        if updated {
            let peer = self.map.read().await.get(id).cloned();
            if let Some(peer) = peer {
                peer.write().await.status = status;
            }
        }
        Ok(updated)
    }

    pub(crate) async fn peer_status(&self, id: &str) -> ResultType<Option<i64>> {
        if let Some(peer) = self.get_in_memory(id).await {
            let peer = peer.read().await;
            if peer.guid.is_empty() {
                return Ok(peer.status);
            }
            return Ok(peer.status);
        }
        Ok(self.db.get_peer(id).await?.and_then(|peer| peer.status))
    }

    pub(crate) async fn is_peer_blocked(&self, id: &str) -> bool {
        matches!(self.peer_status(id).await, Ok(Some(0)))
    }

    pub(crate) async fn is_peer_allowed_for_control(&self, id: &str, company_only: bool) -> bool {
        match self.peer_status(id).await {
            Ok(Some(0)) => false,
            Ok(Some(1)) => true,
            Ok(_) => !company_only,
            Err(err) => {
                log::error!("failed to read peer policy for {}: {}", id, err);
                !company_only
            }
        }
    }

    pub(crate) async fn runtime_snapshot(&self, id: &str) -> Option<PeerRuntimeSnapshot> {
        let peer = self.get_in_memory(id).await?;
        let peer = peer.read().await;
        let elapsed = peer.last_reg_time.elapsed().as_millis() as u64;
        let public_addr = if peer.socket_addr.port() == 0 {
            None
        } else {
            Some(peer.socket_addr.to_string())
        };
        Some(PeerRuntimeSnapshot {
            public_addr,
            last_seen_ms_ago: Some(elapsed),
            online: elapsed < PEER_ONLINE_TIMEOUT_MS,
            registered_ip: if peer.info.ip.is_empty() {
                None
            } else {
                Some(peer.info.ip.clone())
            },
            status: peer.status,
        })
    }
}
