// SPDX-License-Identifier: GPL-3.0-or-later
//! Flatpak sandbox metadata.
//!
//! Callers are identified like xdg-desktop-portal does: by the
//! `/.flatpak-info` in the caller's root, which Flatpak writes outside the
//! sandbox and a sandboxed app can't replace. The file must also match the
//! live instance Flatpak recorded in `$XDG_RUNTIME_DIR/.flatpak/<id>/`,
//! including the sandbox's mount namespace, so a host process can't pass a
//! copied file off as an app's.
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_INFO: u64 = 256 * 1024;

/// The app ID of a caller running in a Flatpak sandbox, or `None` for host
/// processes and anything that can't be verified.
pub fn app_id(pid: u32) -> Option<String> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    // A host process shares Signet's root, where no sandbox metadata belongs.
    let ours = fs::metadata("/").ok()?;
    let theirs = fs::metadata(proc.join("root")).ok()?;
    if (ours.dev(), ours.ino()) == (theirs.dev(), theirs.ino()) {
        return None;
    }
    let info = read_regular(&proc.join("root/.flatpak-info"))?;
    let (app_id, instance) = application(&info)?;
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())?;
    let record = runtime.join(".flatpak").join(&instance);
    if fs::symlink_metadata(&record).ok()?.uid() != unsafe { libc::geteuid() } {
        return None;
    }
    if read_regular(&record.join("info"))? != info {
        return None;
    }
    let bwrap: serde_json::Value =
        serde_json::from_slice(&read_regular(&record.join("bwrapinfo.json"))?).ok()?;
    let recorded = bwrap.get("mnt-namespace")?.as_u64()?;
    (mount_namespace(&proc)? == recorded).then_some(app_id)
}

/// Whether Signet itself runs in a Flatpak sandbox.
pub fn sandboxed() -> bool {
    Path::new("/.flatpak-info").exists()
}

/// Whether Signet's own sandbox can write `~/.gnupg`. Native installs can.
pub fn can_write_standard_gnupg_home() -> bool {
    let Some(info) = read_regular(Path::new("/.flatpak-info")) else {
        return !sandboxed();
    };
    let Some(groups) = parse(&info) else {
        return false;
    };
    grants_gnupg_home(groups.get("Context").and_then(|c| c.get("filesystems")))
}

fn grants_gnupg_home(filesystems: Option<&String>) -> bool {
    filesystems.is_some_and(|list| {
        list.split(';').any(|entry| {
            let (path, mode) = entry.split_once(':').unwrap_or((entry, "rw"));
            matches!(path, "host" | "home" | "~" | "~/.gnupg") && mode != "ro"
        })
    })
}

fn mount_namespace(proc: &Path) -> Option<u64> {
    let link = fs::read_link(proc.join("ns/mnt")).ok()?;
    link.to_str()?
        .strip_prefix("mnt:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn read_regular(path: &Path) -> Option<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_INFO {
        return None;
    }
    let mut data = Vec::new();
    file.take(MAX_INFO + 1).read_to_end(&mut data).ok()?;
    (data.len() as u64 <= MAX_INFO).then_some(data)
}

/// The app ID and instance ID of an application sandbox. Runtime sandboxes
/// and malformed files give `None`.
fn application(info: &[u8]) -> Option<(String, String)> {
    let groups = parse(info)?;
    let name = groups.get("Application")?.get("name")?;
    let instance = groups.get("Instance")?.get("instance-id")?;
    (valid_app_id(name) && valid_instance_id(instance)).then(|| (name.clone(), instance.clone()))
}

/// Flatpak writes this file with GLib, so duplicate groups or keys and
/// stray lines never occur in a genuine one and are rejected.
fn parse(info: &[u8]) -> Option<BTreeMap<String, BTreeMap<String, String>>> {
    let text = std::str::from_utf8(info).ok()?;
    if text.contains('\0') {
        return None;
    }
    let mut groups: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current = None;
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            if groups.insert(name.to_owned(), BTreeMap::new()).is_some() {
                return None;
            }
            current = Some(name.to_owned());
            continue;
        }
        let (key, value) = line.split_once('=')?;
        let group = groups.get_mut(current.as_ref()?)?;
        if group.insert(key.to_owned(), value.to_owned()).is_some() {
            return None;
        }
    }
    Some(groups)
}

/// Flatpak's application name rules: three or more elements of ASCII
/// letters, digits and `_`, none starting with a digit, `-` only in the
/// last element, at most 255 bytes.
fn valid_app_id(id: &str) -> bool {
    let elements: Vec<&str> = id.split('.').collect();
    let last = elements.len().saturating_sub(1);
    id.len() <= 255
        && elements.len() >= 3
        && elements.iter().enumerate().all(|(i, element)| {
            let dash = i == last;
            let mut chars = element.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || (dash && c == '-'))
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || (dash && c == '-'))
        })
}

/// Flatpak allocates instance IDs as decimal 32-bit numbers.
fn valid_instance_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 10
        && id.bytes().all(|b| b.is_ascii_digit())
        && id.parse::<u32>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_application_metadata() {
        let info = b"[Application]\nname=org.gnome.Evolution\nruntime=runtime/org.gnome.Platform/x86_64/49\n\n[Instance]\ninstance-id=3141592653\n";
        assert_eq!(
            application(info),
            Some(("org.gnome.Evolution".into(), "3141592653".into()))
        );
    }
    #[test]
    fn rejects_runtimes_and_malformed_metadata() {
        for info in [
            "[Runtime]\nname=org.gnome.Platform\n[Instance]\ninstance-id=1\n",
            "[Application]\nname=org.example\n[Instance]\ninstance-id=1\n",
            "[Application]\nname=org.example.1App\n[Instance]\ninstance-id=1\n",
            "[Application]\nname=org.ex-ample.App\n[Instance]\ninstance-id=1\n",
            "[Application]\nname=org.example.App\n[Instance]\ninstance-id=../1\n",
            "[Application]\nname=org.example.App\n[Instance]\ninstance-id=99999999999\n",
            "[Application]\nname=org.example.App\nname=org.other.App\n[Instance]\ninstance-id=1\n",
            "[Application]\nname=org.example.App\n[Application]\nname=org.other.App\n[Instance]\ninstance-id=1\n",
            "name=org.example.App\n[Instance]\ninstance-id=1\n",
        ] {
            assert_eq!(application(info.as_bytes()), None, "{info}");
        }
        assert!(valid_app_id("org.example.My-App"));
    }
    #[test]
    fn standard_home_needs_writable_access() {
        let grants = |list: &str| grants_gnupg_home(Some(&list.to_owned()));
        assert!(grants("xdg-run/gnupg:create;~/.gnupg;"));
        assert!(grants("home;"));
        assert!(grants("~/.gnupg:create;"));
        assert!(!grants("~/.gnupg:ro;"));
        assert!(!grants("xdg-run/gnupg:create;xdg-run/signet:create;"));
        assert!(!grants_gnupg_home(None));
    }
    #[test]
    fn host_processes_have_no_app_id() {
        assert_eq!(app_id(std::process::id()), None);
    }
}
