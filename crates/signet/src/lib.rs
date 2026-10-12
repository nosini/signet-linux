// SPDX-License-Identifier: GPL-3.0-or-later
//! Signet's GnuPG-compatible agent, shared by the command line and the app.
pub mod agent;
mod assuan;
pub mod config;
mod crypto;
pub mod flatpak;
mod keygrip;
pub mod manage;
pub mod prompt;

/// Keeps the master password and unlocked keys out of core dumps by setting
/// the core size limit to zero, which the kernel and systemd-coredump honor.
/// Unlike `PR_SET_DUMPABLE`, this leaves `/proc/<pid>/root` readable, which
/// xdg-desktop-portal needs to identify a Flatpak app.
pub fn disable_core_dumps() -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
