// SPDX-License-Identifier: GPL-3.0-or-later
use adw::prelude::*;
use anyhow::{Context, Result, bail};
use gtk::glib;
use signet::{
    config::Config,
    prompt::{ApprovalRequest, Options, Prompter, sanitize},
};
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const TIMEOUT: Duration = Duration::from_secs(120);
struct Request {
    title: String,
    body: String,
    password: bool,
    deadline: Instant,
    reply: mpsc::SyncSender<Option<Zeroizing<String>>>,
}
pub struct GuiPrompter {
    sender: async_channel::Sender<Request>,
}
impl GuiPrompter {
    pub fn new(window: &adw::ApplicationWindow) -> Self {
        let (sender, receiver) = async_channel::bounded::<Request>(8);
        let window = window.downgrade();
        glib::spawn_future_local(async move {
            while let Ok(request) = receiver.recv().await {
                let Some(remaining) = request.deadline.checked_duration_since(Instant::now())
                else {
                    continue;
                };
                let dialog = adw::AlertDialog::builder()
                    .heading(&request.title)
                    .body(&request.body)
                    .body_use_markup(false)
                    .close_response("cancel")
                    .default_response(if request.password { "allow" } else { "cancel" })
                    .build();
                dialog.add_responses(&[
                    ("cancel", if request.password { "Cancel" } else { "Deny" }),
                    (
                        "allow",
                        if request.password {
                            "Continue"
                        } else {
                            "Allow"
                        },
                    ),
                ]);
                dialog.set_response_appearance("allow", adw::ResponseAppearance::Suggested);
                let entry = gtk::PasswordEntry::builder()
                    .show_peek_icon(true)
                    .activates_default(true)
                    .build();
                if request.password {
                    dialog.set_extra_child(Some(&entry));
                }
                let parent = window.upgrade().filter(|w| w.is_visible());
                tracing::debug!(password = request.password, "presenting prompt");
                let response = glib::future_with_timeout(
                    remaining,
                    dialog.clone().choose_future(parent.as_ref()),
                )
                .await;
                tracing::debug!(?response, "prompt completed");
                // A chosen response already closes the dialog. Only force it
                // closed when the future timed out while it was still open.
                if response.is_err() {
                    dialog.force_close();
                }
                let answer = match response {
                    Ok(response) if response == "allow" && Instant::now() < request.deadline => {
                        Some(Zeroizing::new(entry.text().to_string()))
                    }
                    _ => None,
                };
                entry.set_text("");
                let _ = request.reply.send(answer);
            }
        });
        Self { sender }
    }
    fn ask(&self, title: &str, body: &str, password: bool) -> Result<Zeroizing<String>> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(Request {
                title: title.into(),
                body: body.into(),
                password,
                deadline: Instant::now() + TIMEOUT,
                reply,
            })
            .map_err(|_| anyhow::anyhow!("another prompt is pending or the app has closed"))?;
        receiver
            .recv_timeout(TIMEOUT)
            .context("prompt timed out")?
            .context("prompt cancelled")
    }
    pub fn ask_password(&self, title: &str, body: &str) -> Result<Zeroizing<String>> {
        self.ask(title, body, true)
    }
}
impl Prompter for GuiPrompter {
    fn password(&self, _: &Config, _: &Options) -> Result<Zeroizing<String>> {
        self.ask_password("Unlock Signet", "Enter the master password for your vault.")
    }
    fn approve(&self, _: &Config, request: &ApprovalRequest) -> Result<()> {
        let mut body = format!(
            "Key: {}\nFingerprint: {}\n\nRequesting programs:\n{}\n\nProcess descriptions are not verified identities.",
            sanitize(request.title),
            sanitize(&request.grouped_fingerprint()),
            request
                .caller
                .chain
                .iter()
                .map(|line| sanitize(line))
                .collect::<Vec<_>>()
                .join("\n")
        );
        if !request.description.is_empty() {
            body.push_str(&format!(
                "\n\nRequest details: {}",
                sanitize(request.description)
            ));
        }
        self.ask(
            &format!("Allow {}?", sanitize(request.operation)),
            &body,
            false,
        )?;
        Ok(())
    }
}

pub async fn worker<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let (sender, receiver) = async_channel::bounded(1);
    std::thread::spawn(move || {
        let _ = sender.send_blocking(work());
    });
    match receiver.recv().await {
        Ok(result) => result,
        Err(_) => bail!("background task stopped unexpectedly"),
    }
}
