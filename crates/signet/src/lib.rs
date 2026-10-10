// SPDX-License-Identifier: GPL-3.0-or-later
//! Signet's GnuPG-compatible agent, shared by the command line and the app.
pub mod agent;
mod assuan;
pub mod config;
mod crypto;
mod keygrip;
pub mod manage;
pub mod prompt;
