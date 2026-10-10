// SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::{Context, Result, bail};
use gtk::{gio, glib, prelude::*};
use std::{collections::HashMap, path::PathBuf, time::Duration};

fn flatpak() -> bool {
    std::path::Path::new("/.flatpak-info").exists()
}
fn desktop_path() -> PathBuf {
    signet::config::xdg("XDG_CONFIG_HOME", ".config").join("autostart/eu.nosini.Signet.desktop")
}
fn marker() -> PathBuf {
    signet::config::state_dir().join("autostart")
}
pub fn enabled() -> bool {
    if flatpak() {
        marker().exists()
    } else {
        desktop_path().exists()
    }
}

pub async fn set_enabled(enabled: bool) -> Result<()> {
    if flatpak() {
        let bus = gio::bus_get_future(gio::BusType::Session).await?;
        let token = format!("signet_{}", glib::monotonic_time());
        let sender = bus
            .unique_name()
            .context("session bus has no unique name")?
            .trim_start_matches(':')
            .replace('.', "_");
        let path = format!("/org/freedesktop/portal/desktop/request/{sender}/{token}");
        let (tx, rx) = async_channel::bounded(1);
        let _subscription = bus.subscribe_to_signal(
            Some("org.freedesktop.portal.Desktop"),
            Some("org.freedesktop.portal.Request"),
            Some("Response"),
            Some(&path),
            None,
            gio::DBusSignalFlags::NONE,
            move |signal| {
                let _ = tx.try_send(signal.parameters.clone());
            },
        );
        let options: HashMap<&str, glib::Variant> = HashMap::from([
            ("handle_token", token.to_variant()),
            ("reason", "Signet needs to approve signing and decryption requests while its window is closed.".to_variant()),
            ("autostart", enabled.to_variant()),
            ("commandline", vec!["signet-gui", "--background"].to_variant()),
            ("dbus-activatable", false.to_variant()),
        ]);
        bus.call_future(
            Some("org.freedesktop.portal.Desktop"),
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.Background",
            "RequestBackground",
            Some(&("", options).to_variant()),
            None,
            gio::DBusCallFlags::NONE,
            30_000,
        )
        .await?;
        let response = glib::future_with_timeout(Duration::from_secs(120), rx.recv()).await;
        let response = match response {
            Ok(Ok(response)) => response,
            _ => {
                let _ = bus
                    .call_future(
                        Some("org.freedesktop.portal.Desktop"),
                        &path,
                        "org.freedesktop.portal.Request",
                        "Close",
                        None,
                        None,
                        gio::DBusCallFlags::NONE,
                        5000,
                    )
                    .await;
                bail!("The desktop did not answer the background permission request.");
            }
        };
        let (code, results) = response
            .get::<(u32, HashMap<String, glib::Variant>)>()
            .context("invalid portal response")?;
        if code != 0 {
            bail!("Background permission was cancelled or denied.");
        }
        let granted = results
            .get("autostart")
            .and_then(|v| v.get::<bool>())
            .unwrap_or(false);
        if granted != enabled {
            bail!("The desktop did not apply the requested login setting.");
        }
        if enabled {
            signet::config::private_write(&marker(), b"enabled\n")?;
        } else if marker().exists() {
            std::fs::remove_file(marker())?;
        }
    } else if enabled {
        let mut executable = std::env::current_exe()?;
        // Installing an update can unlink the running binary. Linux then
        // appends this suffix to /proc/self/exe; use its replacement path.
        if !executable.is_file() {
            use std::os::unix::ffi::OsStrExt;
            if let Some(path) = executable
                .as_os_str()
                .as_bytes()
                .strip_suffix(b" (deleted)")
            {
                executable = PathBuf::from(std::ffi::OsStr::from_bytes(path));
            }
        }
        if !executable.is_file() {
            bail!(
                "Signet's executable was removed. Reinstall and reopen it before enabling startup."
            );
        }
        let executable = quote_executable(&executable.to_string_lossy());
        let entry = format!(
            "[Desktop Entry]\nType=Application\nName=Signet\nExec=\"{executable}\" --background\nIcon=eu.nosini.Signet\nTerminal=false\n"
        );
        signet::config::private_write(&desktop_path(), entry.as_bytes())?;
    } else if desktop_path().exists() {
        std::fs::remove_file(desktop_path())?;
    }
    Ok(())
}

// First quote the Exec argument, then encode backslashes for the key file.
fn quote_executable(path: &str) -> String {
    path.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$")
        .replace('%', "%%")
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
