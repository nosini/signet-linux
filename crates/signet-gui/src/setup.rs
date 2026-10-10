// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{prompter::worker, window::Window};
use adw::prelude::*;
use gtk::glib;
use std::{cell::RefCell, path::PathBuf, rc::Rc};
use zeroize::Zeroizing;

pub fn entry(group: &adw::PreferencesGroup, title: &str) -> adw::EntryRow {
    let row = adw::EntryRow::builder().title(title).build();
    group.add(&row);
    row
}
pub fn password(group: &adw::PreferencesGroup, title: &str) -> adw::PasswordEntryRow {
    let row = adw::PasswordEntryRow::builder().title(title).build();
    group.add(&row);
    row
}
pub fn file_button(
    window: &adw::ApplicationWindow,
    label: &str,
) -> (gtk::Button, Rc<RefCell<Option<PathBuf>>>) {
    let button = gtk::Button::with_label(label);
    let path = Rc::new(RefCell::new(None));
    button.connect_clicked(glib::clone!(
        #[weak]
        window,
        #[strong]
        path,
        move |button| {
            let button = button.clone();
            let path = path.clone();
            let window = window.clone();
            glib::spawn_future_local(async move {
                if let Ok(file) = gtk::FileDialog::builder()
                    .title("Choose File")
                    .build()
                    .open_future(Some(&window))
                    .await
                {
                    button.set_label(
                        &file
                            .basename()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "Selected file".into()),
                    );
                    *path.borrow_mut() = file.path();
                }
            });
        }
    ));
    (button, path)
}
pub fn page(window: &Rc<Window>) -> gtk::ScrolledWindow {
    let page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder().title("Welcome to Signet").description("Keep OpenPGP keys in an encrypted KeePass vault. Create a vault or bring one from another device.").build();
    page.add(&group);
    let mode = adw::ComboRow::builder()
        .title("Vault")
        .model(&gtk::StringList::new(&[
            "Create a new vault",
            "Open a vault file",
            "Download from WebDAV",
        ]))
        .build();
    group.add(&mode);
    let (source_button, source) = file_button(&window.widget, "Choose Vault File…");
    group.add(&source_button);
    source_button.set_visible(false);
    let master = password(&group, "Master password");
    let confirm = password(&group, "Confirm master password");
    let (key_button, keyfile) = file_button(&window.widget, "Choose Key File (Optional)…");
    group.add(&key_button);
    let clear_key = gtk::Button::with_label("Clear Key File");
    group.add(&clear_key);
    clear_key.connect_clicked(glib::clone!(
        #[strong]
        keyfile,
        #[weak]
        key_button,
        move |_| {
            *keyfile.borrow_mut() = None;
            key_button.set_label("Choose Key File (Optional)…");
        }
    ));
    let webdav = adw::PreferencesGroup::builder()
        .title("WebDAV")
        .description("Use the full HTTPS URL of the vault file.")
        .visible(false)
        .build();
    page.add(&webdav);
    let url = entry(&webdav, "Vault URL");
    let user = entry(&webdav, "Username");
    let remote_password = password(&webdav, "WebDAV password");
    mode.connect_selected_notify(glib::clone!(
        #[weak]
        source_button,
        #[weak]
        confirm,
        #[weak]
        webdav,
        move |mode| {
            source_button.set_visible(mode.selected() == 1);
            confirm.set_visible(mode.selected() == 0);
            webdav.set_visible(mode.selected() == 2);
        }
    ));
    let start = gtk::Button::with_label("Set Up Vault");
    start.add_css_class("suggested-action");
    group.add(&start);
    start.connect_clicked(glib::clone!(
        #[weak]
        window,
        #[weak]
        page,
        move |_| {
            if mode.selected() == 0 && master.text() != confirm.text() {
                window.error(&anyhow::anyhow!("The master passwords do not match."));
                return;
            }
            let password = Zeroizing::new(master.text().to_string());
            let remote_password_value = Zeroizing::new(remote_password.text().to_string());
            master.set_text("");
            confirm.set_text("");
            remote_password.set_text("");
            let selected = mode.selected();
            let source = source.borrow().clone();
            let keyfile = keyfile.borrow().clone();
            let url = url.text().to_string();
            let user = user.text().to_string();
            page.set_sensitive(false);
            glib::spawn_future_local(glib::clone!(
                #[weak]
                window,
                #[weak]
                page,
                async move {
                    let result = worker(move || {
                        let mut config = signet::manage::new_config(None, None)?;
                        // Copy key files as well: document-portal grants need not survive a restart.
                        let key_copy = if let Some(source) = keyfile {
                            let target = config.vault.parent().unwrap().join("vault.key");
                            if target.exists() {
                                anyhow::bail!("A key file already exists in Signet's storage.");
                            }
                            let bytes = Zeroizing::new(std::fs::read(source)?);
                            signet::config::private_write(&target, &bytes)?;
                            config.keyfile = Some(target.clone());
                            Some(target)
                        } else {
                            None
                        };
                        let result = (|| {
                            match selected {
                                0 => {
                                    signet::manage::initialize(&config, password)?;
                                }
                                1 => signet::manage::initialize_from_file(
                                    &config,
                                    &source.ok_or_else(|| {
                                        anyhow::anyhow!("Choose a vault file first.")
                                    })?,
                                    password,
                                )?,
                                _ => signet::manage::initialize_from_webdav(
                                    &mut config,
                                    url.parse()?,
                                    if user.is_empty() { None } else { Some(user) },
                                    Some(remote_password_value),
                                    password,
                                )?,
                            }
                            Ok(())
                        })();
                        if result.is_err()
                            && !signet::config::config_path().exists()
                            && !config.vault.exists()
                            && let Some(path) = key_copy
                        {
                            let _ = std::fs::remove_file(path);
                        }
                        result
                    })
                    .await;
                    page.set_sensitive(true);
                    match result {
                        Ok(()) => window.start(),
                        Err(error) => window.error(&error),
                    }
                }
            ));
        }
    ));
    gtk::ScrolledWindow::builder().child(&page).build()
}
