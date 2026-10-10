// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    autostart,
    prompter::worker,
    setup::{entry, password},
    window::Window,
};
use adw::prelude::*;
use anyhow::Context;
use gtk::glib;
use std::rc::Rc;
use zeroize::Zeroizing;

pub fn show(window: &Rc<Window>) {
    let Some(handle) = window.handle.borrow().clone() else {
        return;
    };
    let config = match handle.config() {
        Ok(c) => c,
        Err(e) => {
            window.error(&e);
            return;
        }
    };
    let dialog = adw::PreferencesDialog::builder()
        .title("Preferences")
        .build();
    let page = adw::PreferencesPage::new();
    dialog.add(&page);
    let security = adw::PreferencesGroup::builder().title("Security").description("Durations accept values such as 15m or 30s. Remembering approvals allows repeated use without asking again; 0s asks every time, and unidentified callers are never remembered. Without a prompt, any program you run can sign or decrypt while the vault is unlocked.").build();
    page.add(&security);
    let idle = entry(&security, "Lock after idle");
    idle.set_text(&config.lock_after_idle);
    let ask_sign = adw::SwitchRow::builder()
        .title("Ask before signing")
        .active(config.approval.sign)
        .build();
    security.add(&ask_sign);
    let ask_decrypt = adw::SwitchRow::builder()
        .title("Ask before decrypting")
        .active(config.approval.decrypt)
        .build();
    security.add(&ask_decrypt);
    let remember = entry(&security, "Remember approvals");
    remember.set_text(&config.approval.remember);
    let login = adw::SwitchRow::builder()
        .title("Start at login")
        .subtitle("Keep the agent available in the background")
        .active(autostart::enabled())
        .build();
    security.add(&login);
    let webdav = adw::PreferencesGroup::builder()
        .title("WebDAV")
        .description(
            "Leave the URL empty to disable sync. A blank password keeps the saved password.",
        )
        .build();
    page.add(&webdav);
    let url = entry(&webdav, "Vault URL (HTTPS)");
    let user = entry(&webdav, "Username");
    let pass = password(&webdav, "New WebDAV password");
    let interval = entry(&webdav, "Sync interval (0s disables automatic sync)");
    interval.set_text("10m");
    if let Some(remote) = &config.webdav {
        url.set_text(remote.url.as_str());
        user.set_text(remote.username.as_deref().unwrap_or(""));
        interval.set_text(&remote.sync_interval);
    }
    let save = gtk::Button::with_label("Save Preferences");
    save.add_css_class("suggested-action");
    webdav.add(&save);
    save.connect_clicked(glib::clone!(
        #[weak]
        window,
        #[weak]
        dialog,
        #[weak]
        page,
        move |_| {
            let mut config = config.clone();
            config.lock_after_idle = idle.text().to_string();
            config.approval.remember = remember.text().to_string();
            config.approval.sign = ask_sign.is_active();
            config.approval.decrypt = ask_decrypt.is_active();
            let url = url.text().to_string();
            let username = user.text().to_string();
            let password = Zeroizing::new(pass.text().to_string());
            let interval = interval.text().to_string();
            let autostart = login.is_active();
            let valid = (|| -> anyhow::Result<()> {
                config
                    .lock_duration()
                    .context("Lock after idle needs a duration such as 15m or 30s")?;
                config
                    .remember_duration()
                    .context("Remember approvals needs a duration such as 0s or 1m")?;
                humantime::parse_duration(&interval)
                    .context("Sync interval needs a duration such as 10m or 0s")?;
                if !url.is_empty() {
                    signet_vault::sync::WebDavConfig {
                        url: url.parse()?,
                        username: None,
                        password: None,
                    }
                    .validate()?;
                }
                Ok(())
            })();
            if let Err(error) = valid {
                window.error(&error);
                return;
            }
            pass.set_text("");
            let handle = handle.clone();
            page.set_sensitive(false);
            dialog.set_can_close(false);
            glib::spawn_future_local(glib::clone!(
                #[weak]
                window,
                #[weak]
                dialog,
                #[weak]
                page,
                async move {
                    let result = async {
                        worker(move || {
                            if url.is_empty() {
                                signet::manage::clear_webdav(&mut config)?;
                            } else {
                                // Apply the interval before writing the remote settings.
                                let remote = config.webdav.get_or_insert(signet::config::WebDav {
                                    url: url.parse()?,
                                    username: None,
                                    password_command: None,
                                    sync_interval: interval.clone(),
                                });
                                remote.sync_interval = interval;
                                signet::manage::set_webdav(
                                    &mut config,
                                    url.parse()?,
                                    if username.is_empty() {
                                        None
                                    } else {
                                        Some(username)
                                    },
                                    if password.is_empty() {
                                        None
                                    } else {
                                        Some(password)
                                    },
                                )?;
                            }
                            handle.reload()
                        })
                        .await?;
                        if autostart != autostart::enabled() {
                            autostart::set_enabled(autostart).await?;
                        }
                        Ok::<_, anyhow::Error>(())
                    }
                    .await;
                    page.set_sensitive(true);
                    dialog.set_can_close(true);
                    match result {
                        Ok(()) => {
                            dialog.close();
                            window.toast("Preferences saved");
                        }
                        Err(error) => window.error(&error),
                    }
                }
            ));
        }
    ));
    dialog.present(Some(&window.widget));
}
