// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{assuan, config::Config};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashMap,
    fs,
    io::{self, BufReader, Read, Write},
    os::fd::AsRawFd,
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
pub type Options = HashMap<String, String>;
pub fn sanitize(value: &str) -> String {
    value.chars().take(240).map(|c| if c.is_whitespace() { ' ' } else if c.is_control() || matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}') { '\u{fffd}' } else { c }).collect()
}
#[derive(Clone)]
pub struct Caller {
    /// Sanitized descriptions of the requesting process and its parents.
    pub chain: Vec<String>,
    pub executables: Vec<PathBuf>,
    /// The verified Flatpak app ID when the requesting process runs in a
    /// Flatpak sandbox.
    pub app_id: Option<String>,
}
impl Caller {
    pub fn description(&self) -> String {
        self.chain.join(" via ")
    }
    /// Whether approvals for this caller can be remembered.
    pub fn identified(&self) -> bool {
        !self.executables.is_empty() || self.app_id.is_some()
    }
}
/// Shown when the kernel reports no peer process, which happens for clients
/// outside the agent's PID namespace, such as host programs talking to a
/// Flatpak.
pub const UNIDENTIFIED: &str = "a program Signet cannot identify from inside its sandbox";
pub fn caller(mut pid: u32) -> Caller {
    if pid == 0 {
        return Caller {
            chain: vec![UNIDENTIFIED.into()],
            executables: Vec::new(),
            app_id: None,
        };
    }
    let app_id = crate::flatpak::app_id(pid);
    let mut descriptions = Vec::new();
    if let Some(app_id) = &app_id {
        descriptions.push(format!("Flatpak app {app_id}"));
    }
    let mut executables = Vec::new();
    for _ in 0..6 {
        if pid <= 1 {
            break;
        }
        let base = PathBuf::from(format!("/proc/{pid}"));
        let executable =
            fs::read_link(base.join("exe")).unwrap_or_else(|_| PathBuf::from("unknown"));
        let name = executable.file_name().unwrap_or_default().to_string_lossy();
        let args = fs::read(base.join("cmdline")).unwrap_or_default();
        let command = args
            .split(|b| *b == 0)
            .take(5)
            .map(|p| String::from_utf8_lossy(p).to_string())
            .collect::<Vec<_>>()
            .join(" ");
        descriptions.push(format!(
            "{} (pid {pid}) {}",
            sanitize(&name),
            sanitize(&command)
        ));
        executables.push(executable);
        let Ok(stat) = fs::read_to_string(base.join("stat")) else {
            break;
        };
        let Some((_, fields)) = stat.rsplit_once(')') else {
            break;
        };
        let Some(parent) = fields
            .split_whitespace()
            .nth(1)
            .and_then(|p| p.parse::<u32>().ok())
        else {
            break;
        };
        if parent == pid {
            break;
        }
        pid = parent;
    }
    Caller {
        chain: descriptions,
        executables,
        app_id,
    }
}
struct TimedOutput {
    output: ChildStdout,
    deadline: Instant,
}
impl Read for TimedOutput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pinentry timed out",
                ));
            }
            let mut descriptor = libc::pollfd {
                fd: self.output.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut descriptor, 1, 1000) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result > 0 {
                return self.output.read(buffer);
            }
        }
    }
}
struct Pinentry {
    child: Child,
    input: ChildStdin,
    output: BufReader<TimedOutput>,
}
impl Drop for Pinentry {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Pinentry {
    fn open(binary: &str, options: &Options) -> Result<Self> {
        let mut command = Command::new(binary);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for name in [
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "DBUS_SESSION_BUS_ADDRESS",
            "XAUTHORITY",
            "PINENTRY_USER_DATA",
        ] {
            if let Some(value) = options.get(name) {
                command.env(name, value);
            }
        }
        if let Some(value) = options.get("display") {
            command.env("DISPLAY", value);
        }
        let mut child = command.spawn().context("start pinentry")?;
        let input = child.stdin.take().context("pinentry stdin")?;
        let output = BufReader::new(TimedOutput {
            output: child.stdout.take().context("pinentry stdout")?,
            deadline: Instant::now() + Duration::from_secs(120),
        });
        let mut pinentry = Self {
            child,
            input,
            output,
        };
        pinentry.response()?;
        pinentry.command("SETTITLE", "Signet")?;
        for option in ["ttyname", "ttytype", "lc-ctype", "lc-messages"] {
            if let Some(value) = options.get(option) {
                pinentry.command("OPTION", &format!("{option}={value}"))?;
            }
        }
        Ok(pinentry)
    }
    fn response(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let mut data = Zeroizing::new(Vec::new());
        loop {
            let value = Zeroizing::new(assuan::line(&mut self.output)?.context("pinentry closed")?);
            if value.starts_with(b"OK") {
                return Ok(data);
            }
            if value.starts_with(b"ERR") {
                bail!("pinentry cancelled or failed");
            }
            if let Some(part) = value.strip_prefix(b"D ") {
                data.extend(assuan::decode(part, false)?);
            }
            if data.len() > 8192 {
                bail!("pinentry response too large");
            }
        }
    }
    fn command(&mut self, name: &str, value: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.input.write_all(name.as_bytes())?;
        if !value.is_empty() {
            self.input.write_all(b" ")?;
            let mut escaped = Vec::new();
            for c in value.chars() {
                let mut buffer = [0u8; 4];
                let bytes = assuan::escape(c.encode_utf8(&mut buffer).as_bytes());
                if name.len() + escaped.len() + bytes.len() + 2 > 999 {
                    break;
                }
                escaped.extend_from_slice(&bytes);
            }
            self.input.write_all(&escaped)?;
        }
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        self.response()
    }
}
/// What the user is asked to allow. Text fields come from the vault or the
/// client and must be passed through [`sanitize`] before display.
pub struct ApprovalRequest<'a> {
    pub operation: &'a str,
    pub title: &'a str,
    pub fingerprint: &'a str,
    pub caller: &'a Caller,
    pub description: &'a str,
}
impl ApprovalRequest<'_> {
    /// The fingerprint in groups of four characters.
    pub fn grouped_fingerprint(&self) -> String {
        self.fingerprint
            .as_bytes()
            .chunks(4)
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<Vec<_>>()
            .join(" ")
    }
}
/// Asks the user for the vault password and for approval of key use.
pub trait Prompter: Send + Sync {
    fn password(&self, config: &Config, options: &Options) -> Result<Zeroizing<String>>;
    /// Returns an error unless the user allowed the operation.
    fn approve(&self, config: &Config, request: &ApprovalRequest) -> Result<()>;
}
/// Prompts through the pinentry program named in the configuration.
pub struct PinentryPrompter;
impl Prompter for PinentryPrompter {
    fn password(&self, config: &Config, options: &Options) -> Result<Zeroizing<String>> {
        let mut pinentry = Pinentry::open(&config.pinentry, options)?;
        pinentry.command("SETDESC", "Unlock the Signet KeePass vault")?;
        pinentry.command("SETPROMPT", "Master password:")?;
        let bytes = pinentry.command("GETPIN", "")?;
        Ok(Zeroizing::new(std::str::from_utf8(&bytes)?.to_string()))
    }
    fn approve(&self, config: &Config, request: &ApprovalRequest) -> Result<()> {
        let mut text = format!(
            "Allow {}?\nFingerprint: {}\nKey: {}\nRequesting programs: {}\nProcess descriptions are not verified identities.",
            request.operation,
            sanitize(&request.grouped_fingerprint()),
            sanitize(request.title),
            request.caller.description()
        );
        if !request.description.is_empty() {
            text.push_str(&format!(
                "\nRequest details: {}",
                sanitize(request.description)
            ));
        }
        // Confirmation is authorization: clients must not choose its display or terminal.
        let mut trusted = Options::new();
        if let Ok(tty) = std::env::var("GPG_TTY") {
            trusted.insert("ttyname".into(), tty);
        }
        let mut pinentry = Pinentry::open(&config.pinentry, &trusted)?;
        pinentry.command("SETDESC", &text)?;
        pinentry.command("SETOK", "Allow")?;
        pinentry.command("SETCANCEL", "Deny")?;
        pinentry.command("CONFIRM", "")?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn untrusted_prompt_text_stays_on_one_line() {
        let text = sanitize("foo\nbar\r\t\0\u{2028}\u{2029}\u{202e}baz");
        assert!(!text.chars().any(char::is_control));
        assert!(!text.contains(['\u{2028}', '\u{2029}', '\u{202e}']));
        assert_eq!(sanitize(&"x".repeat(1000)).len(), 240);
        assert_eq!(sanitize("100% safe"), "100% safe");
    }
}
