// SPDX-License-Identifier: GPL-3.0-or-later
mod autostart;
mod preferences;
mod prompter;
mod setup;
mod subkeys;
mod window;

use adw::prelude::*;
use gtk::{gio, glib};
use std::{cell::RefCell, rc::Rc};
const APP_ID: &str = "eu.nosini.Signet";

fn main() -> glib::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    // Setup, import and the hosted agent all hold the master password or unlocked keys.
    if let Err(error) = signet::disable_core_dumps() {
        eprintln!("signet-gui: cannot disable core dumps: {error}");
        return glib::ExitCode::FAILURE;
    }
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.add_main_option(
        "background",
        glib::Char::from(b'b'),
        glib::OptionFlags::NONE,
        glib::OptionArg::None,
        "Run the agent without showing the window",
        None,
    );
    let state: Rc<RefCell<Option<Rc<window::Window>>>> = Rc::default();
    let background = Rc::new(std::cell::Cell::new(false));
    app.connect_handle_local_options({
        let background = background.clone();
        move |_, options| {
            background.set(options.contains("background"));
            std::ops::ControlFlow::Continue(())
        }
    });
    app.connect_activate({
        let state = state.clone();
        let background = background.clone();
        move |app| {
            if let Some(window) = state.borrow().as_ref() {
                window.widget.present();
                return;
            }
            let window = window::Window::new(app);
            if !background.get() {
                window.widget.present();
            }
            window.start();
            *state.borrow_mut() = Some(window);
        }
    });
    app.connect_shutdown({
        let state = state.clone();
        move |_| {
            if let Some(window) = state.borrow().as_ref() {
                window.stop();
            }
        }
    });
    let quit = gio::SimpleAction::new("quit", None);
    quit.connect_activate({
        let app = app.downgrade();
        move |_, _| {
            if let Some(app) = app.upgrade() {
                app.quit();
            }
        }
    });
    app.add_action(&quit);
    app.set_accels_for_action("app.quit", &["<Primary>q"]);
    app.run()
}
