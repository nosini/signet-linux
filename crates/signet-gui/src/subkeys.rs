// SPDX-License-Identifier: GPL-3.0-or-later
//! Adding, expiring, revoking, deleting and attaching subkeys.
use crate::{prompter::worker, window::Window};
use adw::prelude::*;
use gtk::{gio, glib};
use signet::agent::KeyInfo;
use signet_vault::{
    SecretState,
    edit::{Algorithm, KeyEdit, KeyPart, RevocationReason, Usage},
};
use std::{
    rc::Rc,
    time::{Duration, SystemTime},
};

struct Subkeys {
    window: Rc<Window>,
    key: KeyInfo,
    dialog: adw::Dialog,
    page: adw::PreferencesPage,
    list: gtk::ListBox,
    overlay: adw::ToastOverlay,
}

pub fn show(window: &Rc<Window>, key: &KeyInfo) {
    let dialog = adw::Dialog::builder()
        .title("Subkeys")
        .content_width(640)
        .content_height(600)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let page = adw::PreferencesPage::new();
    let keys = adw::PreferencesGroup::builder()
        .title(glib::markup_escape_text(&key.title))
        .description("Changes are signed with the primary key. Export the public key again afterwards so others get them.")
        .build();
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    keys.add(&list);
    page.add(&keys);
    let actions = adw::PreferencesGroup::new();
    let add = adw::ButtonRow::builder()
        .title("Add Subkey…")
        .start_icon_name("list-add-symbolic")
        .build();
    let attach = adw::ButtonRow::builder()
        .title("Attach a Key From Another Key…")
        .start_icon_name("insert-link-symbolic")
        .build();
    actions.add(&add);
    actions.add(&attach);
    page.add(&actions);
    let overlay = adw::ToastOverlay::new();
    overlay.set_child(Some(&page));
    toolbar.set_content(Some(&overlay));
    dialog.set_child(Some(&toolbar));
    let this = Rc::new(Subkeys {
        window: window.clone(),
        key: key.clone(),
        dialog,
        page,
        list,
        overlay,
    });
    add.connect_activated(glib::clone!(
        #[weak]
        this,
        move |_| {
            glib::spawn_future_local(async move { this.add().await });
        }
    ));
    attach.connect_activated(glib::clone!(
        #[weak]
        this,
        move |_| {
            glib::spawn_future_local(async move { this.attach().await });
        }
    ));
    // Signal handlers hold weak references; keep the state until closed.
    let keep = std::cell::RefCell::new(Some(this.clone()));
    this.dialog.connect_closed(move |_| {
        keep.borrow_mut().take();
    });
    this.dialog.present(Some(&window.widget));
    glib::spawn_future_local(async move { this.refresh().await });
}

impl Subkeys {
    async fn refresh(self: &Rc<Self>) {
        let Some(handle) = self.window.handle.borrow().clone() else {
            return;
        };
        let fingerprint = self.key.fingerprint.clone();
        match worker(move || handle.key_parts(&fingerprint)).await {
            Ok(parts) => {
                self.list.remove_all();
                for part in parts {
                    self.list.append(&self.row(part));
                }
            }
            Err(error) => self.window.error(&error),
        }
    }

    fn row(self: &Rc<Self>, part: KeyPart) -> adw::ActionRow {
        let mut title = format!("{} · {}", part.algorithm, usage_text(&part));
        if part.primary {
            title = format!("Primary key · {title}");
        }
        let mut state = vec![format!("Created {}", date(part.created))];
        state.push(match part.expires {
            Some(expires) if expires <= SystemTime::now() => format!("Expired {}", date(expires)),
            Some(expires) => format!("Expires {}", date(expires)),
            None => "Never expires".into(),
        });
        if part.revoked {
            state.push("Revoked".into());
        }
        if !part.secret {
            state.push("No secret in the vault".into());
        }
        let row = adw::ActionRow::builder()
            .title(title)
            .subtitle(format!(
                "{}\n{}",
                grouped(&part.fingerprint),
                state.join(" · ")
            ))
            .use_markup(false)
            .subtitle_selectable(true)
            .build();
        let menu = gio::Menu::new();
        menu.append(Some("Change Expiry…"), Some("part.expiry"));
        if !part.primary {
            if !part.revoked {
                menu.append(Some("Revoke…"), Some("part.revoke"));
            }
            menu.append(Some("Delete…"), Some("part.delete"));
        }
        let button = gtk::MenuButton::builder()
            .icon_name("view-more-symbolic")
            .tooltip_text("Change this key")
            .valign(gtk::Align::Center)
            .menu_model(&menu)
            .build();
        button.add_css_class("flat");
        row.add_suffix(&button);
        let group = gio::SimpleActionGroup::new();
        for name in ["expiry", "revoke", "delete"] {
            let action = gio::SimpleAction::new(name, None);
            let part = part.clone();
            action.connect_activate(glib::clone!(
                #[weak(rename_to = this)]
                self,
                move |action, _| {
                    let name = action.name().to_string();
                    let part = part.clone();
                    glib::spawn_future_local(async move {
                        match name.as_str() {
                            "expiry" => this.expiry(&part).await,
                            "revoke" => this.revoke(&part).await,
                            _ => this.delete(&part).await,
                        }
                    });
                }
            ));
            group.add_action(&action);
        }
        row.insert_action_group("part", Some(&group));
        row
    }

    /// Confirms the master password, applies `edit` and shows the result.
    async fn apply(self: &Rc<Self>, edit: KeyEdit, done: &'static str) {
        let Some(handle) = self.window.handle.borrow().clone() else {
            return;
        };
        let prompter = self.window.prompter.clone();
        let fingerprint = self.key.fingerprint.clone();
        self.page.set_sensitive(false);
        let result = worker(move || {
            // A cancelled prompt ends the change without an error.
            let Ok(master) = prompter.ask_password(
                "Confirm Master Password",
                "Enter the vault's master password to change this key.",
            ) else {
                return Ok(false);
            };
            handle.edit_key(&fingerprint, &master, &edit)?;
            Ok(true)
        })
        .await;
        self.page.set_sensitive(true);
        match result {
            Ok(true) => {
                self.overlay.add_toast(adw::Toast::new(done));
                self.refresh().await;
            }
            Ok(false) => {}
            Err(error) => {
                self.window.error(&error);
                self.refresh().await;
            }
        }
    }

    async fn expiry(self: &Rc<Self>, part: &KeyPart) {
        let entry = gtk::Entry::builder()
            .placeholder_text("YYYY-MM-DD")
            .text(part.expires.map(date).unwrap_or_default())
            .activates_default(true)
            .build();
        let dialog = alert(
            "Change Expiry",
            "Enter the date the key expires, or leave it empty so it never expires. You can extend it again later.",
        );
        dialog.set_extra_child(Some(&entry));
        dialog.add_responses(&[("cancel", "Cancel"), ("change", "Change")]);
        dialog.set_response_appearance("change", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("change"));
        if dialog.choose_future(Some(&self.dialog)).await != "change" {
            return;
        }
        let expires = match parse_date(&entry.text()) {
            Ok(expires) => expires,
            Err(error) => return self.window.error(&error),
        };
        let edit = KeyEdit::SetExpiry {
            key: match part.fingerprint.parse() {
                Ok(key) => key,
                Err(error) => return self.window.error(&error),
            },
            expires,
        };
        self.apply(edit, "Expiry changed").await;
    }

    async fn revoke(self: &Rc<Self>, part: &KeyPart) {
        const REASONS: [(&str, RevocationReason); 4] = [
            ("No longer used", RevocationReason::Retired),
            ("Replaced by a new subkey", RevocationReason::Superseded),
            ("Compromised", RevocationReason::Compromised),
            ("No reason given", RevocationReason::Unspecified),
        ];
        let reasons = gtk::DropDown::from_strings(&REASONS.map(|(label, _)| label));
        let message = gtk::Entry::builder()
            .placeholder_text("Comment (optional)")
            .build();
        let fields = gtk::Box::new(gtk::Orientation::Vertical, 8);
        fields.append(&reasons);
        fields.append(&message);
        let dialog = alert(
            "Revoke This Subkey?",
            &format!(
                "{}\n\nOthers stop using it once they get your updated public key. It can still decrypt messages sent to it before. Revoking can't be undone.",
                grouped(&part.fingerprint)
            ),
        );
        dialog.set_extra_child(Some(&fields));
        dialog.add_responses(&[("cancel", "Cancel"), ("revoke", "Revoke")]);
        dialog.set_response_appearance("revoke", adw::ResponseAppearance::Destructive);
        if dialog.choose_future(Some(&self.dialog)).await != "revoke" {
            return;
        }
        let Ok(key) = part.fingerprint.parse() else {
            return;
        };
        let edit = KeyEdit::RevokeSubkey {
            key,
            reason: REASONS[reasons.selected() as usize % REASONS.len()].1,
            message: message.text().trim().to_owned(),
        };
        self.apply(edit, "Subkey revoked").await;
    }

    async fn delete(self: &Rc<Self>, part: &KeyPart) {
        let dialog = alert(
            "Delete This Subkey?",
            &format!(
                "{}\n\nIts secret is removed from the vault and synced devices, so messages encrypted to it can't be decrypted without a backup. If you published this subkey, revoke it instead: deleting doesn't tell anyone to stop using it.",
                grouped(&part.fingerprint)
            ),
        );
        dialog.add_responses(&[("cancel", "Cancel"), ("delete", "Delete")]);
        dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
        if dialog.choose_future(Some(&self.dialog)).await != "delete" {
            return;
        }
        let Ok(key) = part.fingerprint.parse() else {
            return;
        };
        self.apply(KeyEdit::DeleteSubkey { key }, "Subkey deleted")
            .await;
    }

    async fn add(self: &Rc<Self>) {
        let algorithms = gtk::DropDown::from_strings(&Algorithm::ALL.map(Algorithm::name));
        let usage = UsageChecks::new();
        let expires = gtk::Entry::builder()
            .placeholder_text("Expires (YYYY-MM-DD, empty for never)")
            .build();
        let fields = gtk::Box::new(gtk::Orientation::Vertical, 8);
        fields.append(&algorithms);
        fields.append(&usage.widget);
        fields.append(&expires);
        let update = {
            let usage = usage.clone();
            move |algorithms: &gtk::DropDown| {
                let algorithm =
                    Algorithm::ALL[algorithms.selected() as usize % Algorithm::ALL.len()];
                usage.limit(algorithm.can_sign(), algorithm.can_encrypt());
                usage.set(Usage {
                    sign: algorithm.can_sign(),
                    encrypt: !algorithm.can_sign(),
                    authenticate: false,
                });
            }
        };
        update(&algorithms);
        algorithms.connect_selected_notify(update);
        let dialog = alert(
            "Add Subkey",
            "Ed25519 signs and authenticates, Cv25519 encrypts, and RSA does both. Signet creates the subkey and binds it with your primary key.",
        );
        dialog.set_extra_child(Some(&fields));
        dialog.add_responses(&[("cancel", "Cancel"), ("add", "Add")]);
        dialog.set_response_appearance("add", adw::ResponseAppearance::Suggested);
        if dialog.choose_future(Some(&self.dialog)).await != "add" {
            return;
        }
        let expires = match parse_date(&expires.text()) {
            Ok(expires) => expires,
            Err(error) => return self.window.error(&error),
        };
        let edit = KeyEdit::AddSubkey {
            algorithm: Algorithm::ALL[algorithms.selected() as usize % Algorithm::ALL.len()],
            usage: usage.get(),
            expires,
        };
        self.apply(edit, "Subkey added").await;
    }

    async fn attach(self: &Rc<Self>) {
        let Some(handle) = self.window.handle.borrow().clone() else {
            return;
        };
        let target = self.key.fingerprint.clone();
        // Keys with a secret in the vault's other certificates.
        let candidates = worker(move || {
            let mut candidates = Vec::new();
            for key in handle.keys()? {
                if key.fingerprint == target || key.secret != Some(SecretState::Usable) {
                    continue;
                }
                for part in handle.key_parts(&key.fingerprint)? {
                    if part.secret {
                        candidates.push((key.title.clone(), part));
                    }
                }
            }
            // Old encryption subkeys are the usual reason to attach a key.
            candidates
                .sort_by_key(|(_, part): &(String, KeyPart)| (!part.usage.encrypt, part.primary));
            Ok(candidates)
        })
        .await;
        let candidates = match candidates {
            Ok(candidates) if candidates.is_empty() => {
                return self.window.error(&anyhow::anyhow!(
                    "No other key in the vault has a secret to attach. Import the old key first."
                ));
            }
            Ok(candidates) => candidates,
            Err(error) => return self.window.error(&error),
        };
        let labels: Vec<String> = candidates
            .iter()
            .map(|(title, part)| {
                format!(
                    "{title}: {} · {} · {}",
                    part.algorithm,
                    usage_text(part),
                    &part.fingerprint[part.fingerprint.len().saturating_sub(16)..]
                )
            })
            .collect();
        let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
        let source = gtk::DropDown::from_strings(&labels);
        let usage = UsageChecks::new();
        let fields = gtk::Box::new(gtk::Orientation::Vertical, 8);
        fields.append(&source);
        fields.append(&usage.widget);
        let update = {
            let usage = usage.clone();
            let candidates = candidates.clone();
            move |source: &gtk::DropDown| {
                if let Some((_, part)) = candidates.get(source.selected() as usize) {
                    // An encryption key stays an encryption key by default.
                    usage.set(if part.usage.encrypt {
                        Usage {
                            encrypt: true,
                            ..Usage::default()
                        }
                    } else if part.usage == Usage::default() {
                        // A primary key that only certifies can still sign.
                        Usage {
                            sign: true,
                            ..Usage::default()
                        }
                    } else {
                        part.usage
                    });
                }
            }
        };
        update(&source);
        source.connect_selected_notify(update);
        let dialog = alert(
            "Attach a Key",
            "The key becomes a subkey of this key. It keeps its creation time and fingerprint, so messages encrypted to it can still be decrypted. You can remove the old key from the vault afterwards.",
        );
        dialog.set_extra_child(Some(&fields));
        dialog.add_responses(&[("cancel", "Cancel"), ("attach", "Attach")]);
        dialog.set_response_appearance("attach", adw::ResponseAppearance::Suggested);
        if dialog.choose_future(Some(&self.dialog)).await != "attach" {
            return;
        }
        let Some((_, part)) = candidates.get(source.selected() as usize) else {
            return;
        };
        let Ok(key) = part.fingerprint.parse() else {
            return;
        };
        self.apply(
            KeyEdit::AttachSubkey {
                key,
                usage: usage.get(),
            },
            "Key attached",
        )
        .await;
    }
}

/// Sign, encrypt and authenticate check boxes.
#[derive(Clone)]
struct UsageChecks {
    widget: gtk::Box,
    sign: gtk::CheckButton,
    encrypt: gtk::CheckButton,
    authenticate: gtk::CheckButton,
}
impl UsageChecks {
    fn new() -> Self {
        let widget = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let sign = gtk::CheckButton::with_label("Sign");
        let encrypt = gtk::CheckButton::with_label("Encrypt");
        let authenticate = gtk::CheckButton::with_label("Authenticate");
        for check in [&sign, &encrypt, &authenticate] {
            widget.append(check);
        }
        Self {
            widget,
            sign,
            encrypt,
            authenticate,
        }
    }
    fn limit(&self, can_sign: bool, can_encrypt: bool) {
        self.sign.set_sensitive(can_sign);
        self.authenticate.set_sensitive(can_sign);
        self.encrypt.set_sensitive(can_encrypt);
    }
    fn set(&self, usage: Usage) {
        self.sign.set_active(usage.sign);
        self.encrypt.set_active(usage.encrypt);
        self.authenticate.set_active(usage.authenticate);
    }
    fn get(&self) -> Usage {
        let on = |check: &gtk::CheckButton| check.is_sensitive() && check.is_active();
        Usage {
            sign: on(&self.sign),
            encrypt: on(&self.encrypt),
            authenticate: on(&self.authenticate),
        }
    }
}

fn alert(heading: &str, body: &str) -> adw::AlertDialog {
    adw::AlertDialog::builder()
        .heading(heading)
        .body(body)
        .body_use_markup(false)
        .close_response("cancel")
        .default_response("cancel")
        .build()
}

fn usage_text(part: &KeyPart) -> String {
    let mut usage = Vec::new();
    if part.certify {
        usage.push("Certify");
    }
    if part.usage.sign {
        usage.push("Sign");
    }
    if part.usage.encrypt {
        usage.push("Encrypt");
    }
    if part.usage.authenticate {
        usage.push("Authenticate");
    }
    if usage.is_empty() {
        "No usage".into()
    } else {
        usage.join(", ")
    }
}

fn grouped(fingerprint: &str) -> String {
    fingerprint
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The UTC date of `time`, as YYYY-MM-DD.
fn date(time: SystemTime) -> String {
    humantime::format_rfc3339_seconds(time).to_string()[..10].to_owned()
}

/// Parses a YYYY-MM-DD expiry date, the end of that day in UTC. An empty
/// text means the key never expires.
fn parse_date(text: &str) -> anyhow::Result<Option<SystemTime>> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let time = humantime::parse_rfc3339_weak(&format!("{text} 23:59:59")).map_err(|_| {
        anyhow::anyhow!("Enter the expiry date as YYYY-MM-DD, for example 2028-12-31.")
    })?;
    if time <= SystemTime::now() + Duration::from_secs(60) {
        anyhow::bail!("Choose an expiry date in the future.");
    }
    Ok(Some(time))
}
