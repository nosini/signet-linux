// SPDX-License-Identifier: GPL-3.0-or-later
use keepass::{Database, DatabaseKey, db::Times};
use signet_vault::{
    Credentials, Vault,
    sync::{SyncError, SyncOutcome, WebDavConfig, sync},
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tempfile::TempDir;
use tiny_http::{Header, Response, Server};
use zeroize::Zeroizing;

#[derive(Default)]
struct Remote {
    data: Option<Vec<u8>>,
    revision: usize,
    tags: bool,
    races: usize,
    status: Option<u16>,
    requests: Vec<(String, Vec<(String, String)>)>,
}
struct Dav {
    state: Arc<Mutex<Remote>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    url: url::Url,
}
impl Dav {
    fn new(data: Option<Vec<u8>>, tags: bool) -> Self {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}/vault.kdbx", server.server_addr())
            .parse()
            .unwrap();
        let state = Arc::new(Mutex::new(Remote {
            data,
            tags,
            ..Remote::default()
        }));
        let shared = state.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let Some(mut request) = server.recv_timeout(Duration::from_millis(100)).unwrap()
                else {
                    continue;
                };
                let mut state = shared.lock().unwrap();
                let headers = request
                    .headers()
                    .iter()
                    .map(|h| {
                        (
                            h.field.to_string().to_ascii_lowercase(),
                            h.value.to_string(),
                        )
                    })
                    .collect::<Vec<_>>();
                let get_header = |name: &str| {
                    headers
                        .iter()
                        .find(|(n, _)| n == name)
                        .map(|(_, v)| v.as_str())
                };
                let method = request.method().to_string();
                let tag = format!("\"{}\"", state.revision);
                let mut status = state.status.unwrap_or(200);
                let mut body = Vec::new();
                if state.status.is_none() {
                    if method == "GET" {
                        match &state.data {
                            None => status = 404,
                            Some(_) if state.tags && get_header("if-none-match") == Some(&tag) => {
                                status = 304
                            }
                            Some(data) => body = data.clone(),
                        }
                    } else if method == "PUT" {
                        if state.races > 0 {
                            state.races -= 1;
                            state.revision += 1;
                            status = 412;
                        } else if (get_header("if-none-match") == Some("*") && state.data.is_some())
                            || (state.tags && get_header("if-match").is_some_and(|v| v != tag))
                        {
                            status = 412;
                        } else {
                            request.as_reader().read_to_end(&mut body).unwrap();
                            state.data = Some(body.clone());
                            body.clear();
                            state.revision += 1;
                            status = 204;
                        }
                    } else {
                        status = 405;
                    }
                }
                state.requests.push((method, headers));
                let mut response = Response::from_data(body).with_status_code(status);
                if state.tags && matches!(status, 200 | 204 | 304) {
                    response.add_header(
                        Header::from_bytes("ETag", format!("\"{}\"", state.revision)).unwrap(),
                    );
                }
                drop(state);
                request.respond(response).unwrap();
            }
        });
        Self {
            state,
            stop,
            worker: Some(worker),
            url,
        }
    }
    fn config(&self) -> WebDavConfig {
        WebDavConfig {
            url: self.url.clone(),
            username: Some("user".into()),
            password: Some(Zeroizing::new("password".into())),
        }
    }
    fn replace(&self, bytes: Vec<u8>) {
        let mut state = self.state.lock().unwrap();
        state.data = Some(bytes);
        state.revision += 1;
    }
}
impl Drop for Dav {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}
struct Working {
    dir: TempDir,
    creds: Credentials,
}
impl Working {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let creds = Credentials {
            password: Some(Zeroizing::new("master password".into())),
            keyfile: None,
        };
        let mut vault = Vault::create(&dir.path().join("vault.kdbx"), creds.clone()).unwrap();
        vault.database.config.kdf_config = keepass::config::KdfConfig::Aes { rounds: 10 };
        vault.save().unwrap();
        Self { dir, creds }
    }
    fn local(&self) -> std::path::PathBuf {
        self.dir.path().join("vault.kdbx")
    }
    fn state(&self) -> std::path::PathBuf {
        self.dir.path().join("state.json")
    }
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.local()).unwrap()
    }
    fn run(&self, dav: &Dav) -> Result<SyncOutcome, SyncError> {
        sync(&self.local(), &self.state(), &dav.config(), &self.creds)
    }
    fn change(&self, title: &str) {
        let mut vault = Vault::open(&self.local(), self.creds.clone()).unwrap();
        vault
            .database
            .root_mut()
            .add_entry()
            .set_unprotected("Title", title);
        vault.save().unwrap();
    }
    fn remote_change(&self, title: &str) -> Vec<u8> {
        let mut db = Database::parse(&self.bytes(), self.creds.database_key().unwrap()).unwrap();
        db.root_mut().add_entry().set_unprotected("Title", title);
        let mut bytes = Vec::new();
        db.save(&mut bytes, self.creds.database_key().unwrap())
            .unwrap();
        bytes
    }
}
#[test]
fn every_sync_branch_with_and_without_etags() {
    for tags in [false, true] {
        let work = Working::new();
        let dav = Dav::new(None, tags);
        assert_eq!(work.run(&dav).unwrap(), SyncOutcome::CreatedRemote);
        assert!(
            dav.state
                .lock()
                .unwrap()
                .requests
                .iter()
                .any(|(method, headers)| method == "PUT"
                    && headers
                        .iter()
                        .any(|(n, v)| n == "if-none-match" && v == "*"))
        );
        assert_eq!(work.run(&dav).unwrap(), SyncOutcome::UpToDate);
        work.change("local entry");
        assert_eq!(work.run(&dav).unwrap(), SyncOutcome::Pushed);
        let old = work.bytes();
        dav.replace(work.remote_change("remote entry"));
        assert_eq!(work.run(&dav).unwrap(), SyncOutcome::Merged);
        assert_eq!(
            std::fs::read_dir(work.dir.path().join("backups"))
                .unwrap()
                .count(),
            1
        );
        assert_eq!(
            std::fs::read(
                std::fs::read_dir(work.dir.path().join("backups"))
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .path()
            )
            .unwrap(),
            old
        );
        let remote = work.remote_change("another remote entry");
        work.change("another local entry");
        dav.replace(remote);
        assert_eq!(work.run(&dav).unwrap(), SyncOutcome::Merged);
        let vault = Vault::open(&work.local(), work.creds.clone()).unwrap();
        let titles = vault
            .database
            .iter_all_entries()
            .map(|e| e.get_title().unwrap().to_string())
            .collect::<Vec<_>>();
        assert!(titles.contains(&"another remote entry".into()));
        assert!(titles.contains(&"another local entry".into()));
        assert_eq!(work.run(&dav).unwrap(), SyncOutcome::UpToDate);
    }
}
#[test]
fn conditional_upload_retries_and_conflict_exhaustion() {
    let work = Working::new();
    let dav = Dav::new(None, true);
    work.run(&dav).unwrap();
    work.change("change");
    dav.state.lock().unwrap().races = 1;
    assert_eq!(work.run(&dav).unwrap(), SyncOutcome::Pushed);
    work.change("next change");
    let bytes = work.bytes();
    dav.state.lock().unwrap().races = 3;
    assert!(matches!(work.run(&dav), Err(SyncError::Conflict)));
    assert_eq!(work.bytes(), bytes);
}
#[test]
fn authentication_corruption_and_remote_credentials_leave_local_untouched() {
    let work = Working::new();
    let old = work.bytes();
    let dav = Dav::new(None, true);
    for code in [401, 403] {
        dav.state.lock().unwrap().status = Some(code);
        assert!(matches!(work.run(&dav), Err(SyncError::Auth(n)) if n == code));
    }
    dav.state.lock().unwrap().status = None;
    dav.replace(vec![0, 1, 2]);
    assert!(matches!(work.run(&dav), Err(SyncError::CorruptRemote(_))));
    let db = Database::parse(&old, work.creds.database_key().unwrap()).unwrap();
    let mut bytes = Vec::new();
    db.save(
        &mut bytes,
        DatabaseKey::new().with_password("other password"),
    )
    .unwrap();
    dav.replace(bytes);
    assert!(matches!(work.run(&dav), Err(SyncError::RemoteCredentials)));
    assert_eq!(work.bytes(), old);
    assert!(!work.state().exists());
}
#[test]
fn initial_matching_file_needs_no_upload_and_backup_retention_is_five() {
    let work = Working::new();
    let dav = Dav::new(Some(work.bytes()), true);
    assert_eq!(work.run(&dav).unwrap(), SyncOutcome::UpToDate);
    assert!(
        dav.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .all(|(method, _)| method == "GET")
    );
    for i in 0..7 {
        dav.replace(work.remote_change(&format!("remote {i}")));
        assert_eq!(work.run(&dav).unwrap(), SyncOutcome::Merged);
    }
    assert_eq!(
        std::fs::read_dir(work.dir.path().join("backups"))
            .unwrap()
            .count(),
        5
    );
}
#[test]
fn rejects_plaintext_remote_url_and_url_credentials() {
    for url in [
        "http://example.org/vault",
        "https://user:password@example.org/vault",
        "https://example.org/vault#fragment",
    ] {
        let config = WebDavConfig {
            url: url.parse().unwrap(),
            username: None,
            password: None,
        };
        assert!(matches!(config.validate(), Err(SyncError::InvalidUrl)));
    }
    let _ = Times::epoch();
}

// Regression: a remote file that regresses to an earlier version
// replaces a newer, already-synced working copy without merging.
#[test]
fn remote_rollback_keeps_newer_local() {
    let work = Working::new();
    let dav = Dav::new(None, true);
    assert_eq!(work.run(&dav).unwrap(), SyncOutcome::CreatedRemote);
    let first = work.bytes();
    work.change("added after first upload");
    assert_eq!(work.run(&dav).unwrap(), SyncOutcome::Pushed);
    let vault = Vault::open(&work.local(), work.creds.clone()).unwrap();
    let before = vault.database.iter_all_entries().count();
    assert_eq!(before, 1);
    dav.replace(first);
    assert_eq!(work.run(&dav).unwrap(), SyncOutcome::Merged);
    let vault = Vault::open(&work.local(), work.creds.clone()).unwrap();
    assert_eq!(vault.database.iter_all_entries().count(), 1);
    let _ = Times::now();
    let _ = DatabaseKey::new();
}
// Regression: an unrelated vault with the same credentials is pulled
// over the working copy when only the remote changed.
#[test]
fn remote_only_change_rejects_unrelated_root() {
    let work = Working::new();
    let dav = Dav::new(None, true);
    work.change("local key");
    assert_eq!(work.run(&dav).unwrap(), SyncOutcome::CreatedRemote);
    let other_dir = tempfile::tempdir().unwrap();
    let mut other = Vault::create(&other_dir.path().join("o.kdbx"), work.creds.clone()).unwrap();
    other.database.config.kdf_config = keepass::config::KdfConfig::Aes { rounds: 10 };
    other.save().unwrap();
    let local_root = Vault::open(&work.local(), work.creds.clone())
        .unwrap()
        .database
        .root()
        .id();
    assert_ne!(local_root, other.database.root().id());
    dav.replace(std::fs::read(other_dir.path().join("o.kdbx")).unwrap());
    let before = work.bytes();
    assert!(matches!(
        work.run(&dav),
        Err(SyncError::Merge(
            signet_vault::merge::MergeError::DifferentRoots
        ))
    ));
    assert_eq!(before, work.bytes());
    let vault = Vault::open(&work.local(), work.creds.clone()).unwrap();
    assert_eq!(vault.database.iter_all_entries().count(), 1);
    assert_eq!(vault.database.root().id(), local_root);
}
