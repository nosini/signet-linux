// SPDX-License-Identifier: GPL-3.0-or-later
//! Exercises the API used by the desktop app in an isolated subprocess.
use anyhow::Result;
use signet::{
    agent::Agent,
    config, manage,
    prompt::{ApprovalRequest, Options, Prompter},
};
use signet_vault::{Credentials, Vault};
use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;
struct TestPrompter;
impl Prompter for TestPrompter {
    fn password(&self, _: &config::Config, _: &Options) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new("test".into()))
    }
    fn approve(&self, _: &config::Config, _: &ApprovalRequest) -> Result<()> {
        anyhow::bail!("denied")
    }
}
#[test]
fn hosted_agent_and_file_setup() {
    if std::env::var_os("SIGNET_HOSTED_TEST").is_none() {
        let dir = tempfile::tempdir().unwrap();
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "hosted_agent_and_file_setup", "--nocapture"])
            .env("SIGNET_HOSTED_TEST", "1")
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .env("XDG_RUNTIME_DIR", dir.path().join("run"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let config = manage::new_config(None, None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.kdbx");
    let creds = Credentials {
        password: Some(Zeroizing::new("test".into())),
        keyfile: None,
    };
    let mut vault = Vault::create(&source, creds.clone()).unwrap();
    use sequoia_openpgp::{cert::CertBuilder, serialize::Serialize};
    let (cert, _) = CertBuilder::new()
        .add_userid("Test <test@example.org>")
        .add_signing_subkey()
        .generate()
        .unwrap();
    let mut fixture = Vec::new();
    cert.as_tsk().armored().serialize(&mut fixture).unwrap();
    vault.import(&fixture, &mut |_| None).unwrap();
    vault.save().unwrap();
    let original = std::fs::read(&source).unwrap();
    assert!(
        manage::initialize_from_file(&config, &source, Zeroizing::new("wrong".into())).is_err()
    );
    assert!(!config.vault.exists());
    assert!(!config::config_path().exists());
    // A failed configuration write must leave both setup paths retryable.
    let config_parent = config::config_path().parent().unwrap().to_owned();
    std::fs::create_dir_all(config_parent.parent().unwrap()).unwrap();
    std::fs::write(&config_parent, b"blocks config directory").unwrap();
    assert!(manage::initialize(&config, Zeroizing::new("test".into())).is_err());
    assert!(!config.vault.exists());
    assert!(manage::initialize_from_file(&config, &source, Zeroizing::new("test".into())).is_err());
    assert!(!config.vault.exists());
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_file(config_parent).unwrap();
    manage::initialize_from_file(&config, &source, Zeroizing::new("test".into())).unwrap();
    assert_eq!(std::fs::read(&source).unwrap(), original);
    assert_eq!(std::fs::read(&config.vault).unwrap(), original);
    assert!(manage::initialize_from_file(&config, &source, Zeroizing::new("test".into())).is_err());
    let agent = Agent::start(config.clone(), Arc::new(TestPrompter)).unwrap();
    let handle = agent.handle();
    let stop: Arc<AtomicBool> = agent.stop_flag();
    let serving = std::thread::spawn(move || agent.serve().unwrap());
    assert!(Agent::start(config, Arc::new(TestPrompter)).is_err());
    assert!(handle.status().unwrap().locked);
    handle.unlock().unwrap();
    let keys = handle.keys().unwrap();
    assert!(!keys.is_empty());
    let fp = keys[0].fingerprint.clone();
    assert!(
        handle
            .export_public(&fp)
            .unwrap()
            .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    );
    handle.setup_gnupg().unwrap();
    handle.lock().unwrap();
    assert!(handle.status().unwrap().locked);
    handle.unlock().unwrap();
    handle.remove(&fp).unwrap();
    assert!(handle.keys().unwrap().is_empty());
    // An empty vault still gets a GnuPG home; gpg itself rejects empty input.
    handle.setup_gnupg().unwrap();
    assert!(!Vault::open(&source, creds).unwrap().keys().is_empty());
    stop.store(true, Ordering::Relaxed);
    serving.join().unwrap();
}
