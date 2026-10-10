// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    preferences,
    prompter::{GuiPrompter, worker},
    setup,
};
use adw::prelude::*;
use gtk::{gio, glib};
use signet::{
    agent::{Agent, Handle, KeyInfo},
    config::Config,
    manage,
};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub struct Window {
    // Hold only the primary instance that owns the agent. A launcher that
    // activates an existing instance must be able to exit immediately.
    _hold: gio::ApplicationHoldGuard,
    pub widget: adw::ApplicationWindow,
    pub prompter: Arc<GuiPrompter>,
    pub handle: RefCell<Option<Handle>>,
    stop: RefCell<Option<Arc<AtomicBool>>>,
    stack: gtk::Stack,
    status: gtk::Label,
    keys: gtk::ListBox,
    overlay: adw::ToastOverlay,
    actions: gtk::Box,
    lock: gtk::Button,
    busy: Cell<bool>,
    last_keys: RefCell<String>,
}
impl Window {
    pub fn new(app: &adw::Application) -> Rc<Self> {
        let widget = adw::ApplicationWindow::builder()
            .application(app)
            .title("Signet")
            .default_width(760)
            .default_height(640)
            .hide_on_close(true)
            .build();
        let prompter = Arc::new(GuiPrompter::new(&widget));
        let toolbar = adw::ToolbarView::new();
        let header = adw::HeaderBar::new();
        let menu = gio::Menu::new();
        menu.append(Some("Quit Signet"), Some("app.quit"));
        let menu_button = gtk::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .menu_model(&menu)
            .build();
        header.pack_end(&menu_button);
        toolbar.add_top_bar(&header);
        let stack = gtk::Stack::new();
        let overlay = adw::ToastOverlay::new();
        overlay.set_child(Some(&stack));
        toolbar.set_content(Some(&overlay));
        widget.set_content(Some(&toolbar));
        let main = gtk::Box::new(gtk::Orientation::Vertical, 18);
        main.set_margin_top(24);
        main.set_margin_bottom(24);
        main.set_margin_start(24);
        main.set_margin_end(24);
        let status = gtk::Label::builder()
            .label("Starting Signet…")
            .wrap(true)
            .xalign(0.0)
            .build();
        main.append(&status);
        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let unlock = gtk::Button::with_label("Unlock");
        let lock = gtk::Button::with_label("Lock");
        let import = gtk::Button::with_label("Import Key…");
        let sync = gtk::Button::with_label("Sync");
        let prefs = gtk::Button::with_label("Preferences");
        for button in [&unlock, &import, &sync, &prefs] {
            actions.append(button);
        }
        let action_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        action_row.append(&actions);
        action_row.append(&lock);
        main.append(&action_row);
        let keys = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .build();
        keys.add_css_class("boxed-list");
        let empty = adw::StatusPage::builder()
            .title("Your OpenPGP keys")
            .description("Unlock your vault to view all keys, or import a key to get started.")
            .icon_name("dialog-password-symbolic")
            .build();
        keys.set_placeholder(Some(&empty));
        let scroll = gtk::ScrolledWindow::builder()
            .vexpand(true)
            .child(&keys)
            .build();
        main.append(&scroll);
        let integration = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let gnupg = gtk::Button::with_label("Set Up GnuPG");
        let home = gtk::Button::with_label("Copy GNUPGHOME");
        integration.append(&gnupg);
        integration.append(&home);
        main.append(&integration);
        let note = gtk::Label::builder()
            .label("Closing this window keeps Signet running. Use the menu to quit.")
            .wrap(true)
            .xalign(0.0)
            .build();
        note.add_css_class("dim-label");
        main.append(&note);
        stack.add_named(&main, Some("main"));
        let this = Rc::new(Self {
            _hold: app.hold(),
            widget,
            prompter,
            handle: RefCell::new(None),
            stop: RefCell::new(None),
            stack,
            status,
            keys,
            overlay,
            actions,
            lock,
            busy: Cell::new(false),
            last_keys: RefCell::new(String::new()),
        });
        unlock.connect_clicked(glib::clone!(
            #[weak]
            this,
            move |_| {
                this.run("Vault unlocked", |h| h.unlock());
            }
        ));
        this.lock.connect_clicked(glib::clone!(
            #[weak]
            this,
            move |_| {
                if let Some(handle) = this.handle.borrow().clone() {
                    glib::spawn_future_local(glib::clone!(
                        #[weak]
                        this,
                        async move {
                            if let Err(error) = worker(move || handle.lock()).await {
                                this.error(&error);
                            }
                        }
                    ));
                }
            }
        ));
        sync.connect_clicked(glib::clone!(
            #[weak]
            this,
            move |_| {
                this.run("Vault synced", |h| h.sync());
            }
        ));
        gnupg.connect_clicked(glib::clone!(
            #[weak]
            this,
            move |_| {
                this.run("GnuPG is ready. Copy GNUPGHOME for your shell.", |h| {
                    h.setup_gnupg().map(|_| ())
                });
            }
        ));
        home.connect_clicked(glib::clone!(
            #[weak]
            this,
            move |_| {
                if let Some(h) = this.handle.borrow().as_ref() {
                    match h.config() {
                        Ok(c) => this.copy(&manage::gnupghome_export(&c)),
                        Err(e) => this.error(&e),
                    }
                }
            }
        ));
        prefs.connect_clicked(glib::clone!(
            #[weak]
            this,
            move |_| {
                preferences::show(&this);
            }
        ));
        import.connect_clicked(glib::clone!(
            #[weak]
            this,
            move |_| {
                this.import();
            }
        ));
        this
    }
    pub fn start(self: &Rc<Self>) {
        if !signet::config::config_path().exists() {
            let setup = setup::page(self);
            self.stack.add_named(&setup, Some("setup"));
            self.stack.set_visible_child_name("setup");
            return;
        }
        self.stack.set_visible_child_name("main");
        let this = self.clone();
        let prompter = self.prompter.clone();
        glib::spawn_future_local(async move {
            match worker(move || Agent::start(Config::read()?, prompter)).await {
                Ok(agent) => {
                    *this.handle.borrow_mut() = Some(agent.handle());
                    *this.stop.borrow_mut() = Some(agent.stop_flag());
                    let weak = Rc::downgrade(&this);
                    glib::spawn_future_local(async move {
                        let result = worker(move || agent.serve()).await;
                        if let Some(this) = weak.upgrade() {
                            this.start_error(
                                &result
                                    .err()
                                    .unwrap_or_else(|| anyhow::anyhow!("The agent stopped.")),
                            );
                        }
                    });
                    this.poll();
                }
                Err(error) => this.start_error(&error),
            }
        });
    }
    fn start_error(&self, error: &anyhow::Error) {
        let page = adw::StatusPage::builder().title("Signet could not start").description(format!("{error:#}\n\nIf the command-line agent is running, stop it first:\nsystemctl --user disable --now signet.service\n\nThen quit and reopen Signet.")).icon_name("dialog-error-symbolic").build();
        self.stack.add_named(&page, Some("error"));
        self.stack.set_visible_child_name("error");
        self.widget.present();
    }
    pub fn stop(&self) {
        if let Some(stop) = self.stop.borrow().as_ref() {
            stop.store(true, Ordering::Relaxed);
        }
    }
    fn poll(self: &Rc<Self>) {
        let weak = Rc::downgrade(self);
        glib::spawn_future_local(async move {
            loop {
                let Some(this) = weak.upgrade() else { break };
                let Some(handle) = this.handle.borrow().clone() else {
                    break;
                };
                match worker(move || Ok((handle.status()?, handle.keys()?))).await {
                    Ok((status, keys)) => {
                        this.status.set_text(&format!(
                            "{} · {}\n{}",
                            if status.locked {
                                "Vault locked"
                            } else {
                                "Vault unlocked"
                            },
                            if status.webdav {
                                "WebDAV enabled"
                            } else {
                                "Local vault"
                            },
                            status
                                .last_sync
                                .map(|s| format!("Last sync: {s}"))
                                .unwrap_or_default()
                        ));
                        let signature = format!("{keys:?}");
                        if *this.last_keys.borrow() != signature {
                            this.render_keys(keys);
                            *this.last_keys.borrow_mut() = signature;
                        }
                    }
                    Err(error) => this.status.set_text(&format!("{error:#}")),
                }
                drop(this);
                glib::timeout_future_seconds(1).await;
            }
        });
    }
    fn render_keys(self: &Rc<Self>, keys: Vec<KeyInfo>) {
        self.keys.set_placeholder(None::<&gtk::Widget>);
        self.keys.remove_all();
        if keys.is_empty() {
            let empty = adw::StatusPage::builder()
                .title("Your OpenPGP keys")
                .description("Unlock your vault to view all keys, or import a key to get started.")
                .icon_name("dialog-password-symbolic")
                .build();
            self.keys.set_placeholder(Some(&empty));
        }
        for key in keys {
            let row = adw::ActionRow::builder()
                .title(&key.title)
                .subtitle(&key.fingerprint)
                .use_markup(false)
                .subtitle_selectable(true)
                .build();
            let button = gtk::Button::builder()
                .icon_name("go-next-symbolic")
                .tooltip_text("Key details")
                .valign(gtk::Align::Center)
                .build();
            row.add_suffix(&button);
            row.set_activatable_widget(Some(&button));
            button.connect_clicked(glib::clone!(
                #[weak(rename_to = this)]
                self,
                move |_| {
                    this.key_dialog(&key);
                }
            ));
            self.keys.append(&row);
        }
    }
    fn key_dialog(self: &Rc<Self>, key: &KeyInfo) {
        let dialog = adw::AlertDialog::builder()
            .heading(&key.title)
            .body(format!(
                "{}\n\n{}\n\n{}",
                key.fingerprint,
                key.user_ids.join("\n"),
                match key.secret {
                    None => "Unlock to see key details",
                    Some(signet_vault::SecretState::Usable) => "Secret key available",
                    Some(signet_vault::SecretState::None) => "Public key only",
                    _ => "Secret key is not usable",
                }
            ))
            .body_use_markup(false)
            .close_response("close")
            .build();
        dialog.add_responses(&[
            ("close", "Close"),
            ("fingerprint", "Copy Fingerprint"),
            ("public", "Copy Public Key"),
            ("save", "Save Public Key…"),
            ("git", "Copy Git Commands"),
            ("remove", "Remove Key…"),
        ]);
        dialog.set_response_appearance("remove", adw::ResponseAppearance::Destructive);
        let key = key.clone();
        let this = self.clone();
        glib::spawn_future_local(async move {
            match dialog.choose_future(Some(&this.widget)).await.as_str() {
                "fingerprint" => this.copy(&key.fingerprint),
                "git" => {
                    if let Some(h) = this.handle.borrow().as_ref() {
                        match h.config() { Ok(config) => this.copy(&format!("{}\ngit config --global gpg.format openpgp\ngit config --global user.signingkey {}\ngit config --global commit.gpgsign true", manage::gnupghome_export(&config), key.fingerprint)), Err(e) => this.error(&e) }
                    }
                }
                "remove" => {
                    let confirm = adw::AlertDialog::builder().heading("Remove this key?").body(format!("{}\n{}\n\nThe key will be removed from the vault and synced devices. Keep a separate backup if you need it again.", key.title, key.fingerprint)).body_use_markup(false).default_response("cancel").close_response("cancel").build();
                    confirm.add_responses(&[("cancel", "Cancel"), ("remove", "Remove")]);
                    confirm.set_response_appearance("remove", adw::ResponseAppearance::Destructive);
                    if confirm.choose_future(Some(&this.widget)).await == "remove" {
                        this.run("Key removed", move |h| h.remove(&key.fingerprint));
                    }
                }
                action @ ("public" | "save") => {
                    let save = action == "save";
                    let Some(handle) = this.handle.borrow().clone() else {
                        return;
                    };
                    match worker(move || handle.export_public(&key.fingerprint)).await {
                        Ok(public) if !save => this.copy(&public),
                        Ok(public) => {
                            let chooser = gtk::FileDialog::builder()
                                .title("Save Public Key")
                                .initial_name("public-key.asc")
                                .build();
                            if let Ok(file) = chooser.save_future(Some(&this.widget)).await
                                && let Err(error) = file
                                    .replace_contents_future(
                                        public.into_bytes(),
                                        None,
                                        false,
                                        gio::FileCreateFlags::REPLACE_DESTINATION,
                                    )
                                    .await
                            {
                                this.error(&anyhow::anyhow!("{}", error.1));
                            }
                        }
                        Err(error) => this.error(&error),
                    }
                }
                _ => {}
            }
        });
    }
    fn import(self: &Rc<Self>) {
        let this = self.clone();
        glib::spawn_future_local(async move {
            let chooser = gtk::FileDialog::builder()
                .title("Import OpenPGP Key")
                .build();
            let Ok(file) = chooser.open_future(Some(&this.widget)).await else {
                return;
            };
            let Some(path) = file.path() else {
                this.error(&anyhow::anyhow!(
                    "The selected file is not locally accessible."
                ));
                return;
            };
            let prompter = this.prompter.clone();
            this.run("Key imported and GnuPG updated", move |handle| {
                let data = zeroize::Zeroizing::new(std::fs::read(path)?);
                handle.import(&data, &mut |_| {
                    prompter
                        .ask_password(
                            "Unlock Imported Key",
                            "Enter the passphrase protecting the OpenPGP secret key.",
                        )
                        .ok()
                })?;
                handle.setup_gnupg().map_err(|e| {
                    anyhow::anyhow!(
                        "Key imported, but GnuPG setup failed: {e:#}. Use Set Up GnuPG to retry."
                    )
                })?;
                Ok(())
            });
        });
    }
    pub fn run(
        self: &Rc<Self>,
        message: &'static str,
        task: impl FnOnce(Handle) -> anyhow::Result<()> + Send + 'static,
    ) {
        if self.busy.replace(true) {
            return;
        }
        let Some(handle) = self.handle.borrow().clone() else {
            self.busy.set(false);
            return;
        };
        self.actions.set_sensitive(false);
        let this = self.clone();
        glib::spawn_future_local(async move {
            let result = worker(move || task(handle)).await;
            this.busy.set(false);
            this.actions.set_sensitive(true);
            match result {
                Ok(()) => this.toast(message),
                Err(error) => this.error(&error),
            }
        });
    }
    pub fn copy(&self, text: &str) {
        self.widget.clipboard().set_text(text);
        self.toast("Copied to clipboard");
    }
    pub fn toast(&self, message: &str) {
        self.overlay.add_toast(adw::Toast::new(message));
    }
    pub fn error(&self, error: &anyhow::Error) {
        let dialog = adw::AlertDialog::builder()
            .heading("Could not complete the operation")
            .body(format!("{error:#}"))
            .body_use_markup(false)
            .build();
        dialog.add_response("close", "Close");
        dialog.present(Some(&self.widget));
    }
}
