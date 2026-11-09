// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The hub's UDP port in the firewall, as the Go cbb's hubport.go. A hub
//! reached at its own address takes its clients on a UDP port from the
//! internet, which a firewall at home drops. The installers open only the
//! ports the home network needs, so cbb global hub lists that one rule and
//! asks before it opens it, as the installers ask for theirs: it faces the
//! internet, so it is asked for on its own. The port stays open while this
//! device is a hub reached at its own address, and cbb closes it when that
//! ends (another port, a forwarder, cbb global off). The rule cbb opened is
//! remembered by the system's way (Linux: /etc/cbb/firewall.hub through
//! firewall.sh; Windows: the rule cbb-hub); the Mac's application firewall
//! allows a listed program on every port already.

use std::io::Write;

use crate::control::Away;
use crate::error::{Error, Result};

/// Runs a PowerShell script and returns its output, trimmed.
pub(crate) fn powershell(script: &str) -> Result<String> {
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| Error::msg(format!("powershell: {e}")))?;
    let text = String::from_utf8_lossy(&[out.stdout.as_slice(), out.stderr.as_slice()].concat()).trim().to_string();
    if !out.status.success() {
        return Err(Error::msg(format!("powershell: {}: {text}", out.status)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// One system's firewall, for the hub's port.
pub(crate) trait Firewall {
    /// The firewall, for the messages.
    fn name(&self) -> &'static str;
    /// A firewall filters incoming packets here.
    fn active(&self) -> bool;
    /// The port cbb opened, or 0.
    fn opened(&self) -> i64;
    /// Opens it.
    fn open(&self, port: i64) -> Result<()>;
    /// Closes what cbb opened.
    fn close(&self) -> Result<()>;
    /// What opens it by hand.
    fn commands(&self, port: i64) -> Vec<String>;
}

/// The installer's firewall.sh: under /usr/local/share, /usr/share on
/// OpenWrt, which has no /usr/local, or /opt on SteamOS.
fn firewall_script() -> &'static str {
    if crate::openwrt() {
        return "/usr/share/cbb/firewall.sh";
    }
    let exe = std::env::current_exe().ok().and_then(|e| std::fs::canonicalize(e).ok());
    if exe.is_some_and(|e| e == std::path::Path::new("/opt/cbb/bin/cbb")) {
        return "/opt/cbb/share/firewall.sh";
    }
    "/usr/local/share/cbb/firewall.sh"
}

/// Linux and FreeBSD: the installer's firewall.sh.
struct Script;

impl Script {
    fn run(&self, args: &[&str]) -> Result<String> {
        let out = std::process::Command::new("sh")
            .arg(firewall_script())
            .args(args)
            .stderr(std::process::Stdio::null())
            .output()
            .map_err(|e| Error::msg(format!("firewall.sh: {e}")))?;
        if !out.status.success() {
            return Err(Error::msg(format!("firewall.sh {}: {}", args.join(" "), out.status)));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

impl Firewall for Script {
    fn name(&self) -> &'static str {
        "the firewall"
    }

    fn active(&self) -> bool {
        self.run(&["kind"]).is_ok_and(|k| k != "none")
    }

    fn opened(&self) -> i64 {
        self.run(&["hub-port"]).ok().and_then(|p| p.parse().ok()).unwrap_or(0)
    }

    fn open(&self, port: i64) -> Result<()> {
        self.run(&["hub-open", &port.to_string()]).map(|_| ())
    }

    fn close(&self) -> Result<()> {
        self.run(&["hub-close"]).map(|_| ())
    }

    fn commands(&self, port: i64) -> Vec<String> {
        match self.run(&["hub-commands", &port.to_string()]) {
            Ok(out) if !out.is_empty() => out.lines().map(String::from).collect(),
            _ => Vec::new(),
        }
    }
}

/// The rule cbb opens on Windows.
const HUB_RULE: &str = "cbb-hub";

fn windows_rule(port: i64) -> String {
    format!(
        "New-NetFirewallRule -Name '{HUB_RULE}' -Group 'cbb' -DisplayName 'CBB hub (UDP {port})' -Direction Inbound -Action Allow -Protocol UDP -LocalPort {port} -Program \"$env:ProgramFiles\\cbb\\cbb.exe\" -Profile Any"
    )
}

/// Windows Firewall, always on.
struct WindowsFirewall;

impl Firewall for WindowsFirewall {
    fn name(&self) -> &'static str {
        "Windows Firewall"
    }

    fn active(&self) -> bool {
        true
    }

    fn opened(&self) -> i64 {
        powershell(&format!(
            "[string](Get-NetFirewallRule -Name '{HUB_RULE}' -ErrorAction SilentlyContinue | Get-NetFirewallPortFilter).LocalPort"
        ))
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0)
    }

    fn open(&self, port: i64) -> Result<()> {
        let script = format!(
            "$ErrorActionPreference = 'Stop'\nRemove-NetFirewallRule -Name '{HUB_RULE}' -ErrorAction SilentlyContinue\n{} -Description 'The group''s devices away from home reach the CBB hub here, through its WireGuard tunnel.' | Out-Null\n",
            windows_rule(port)
        );
        powershell(&script).map(|_| ())
    }

    fn close(&self) -> Result<()> {
        powershell(&format!("Remove-NetFirewallRule -Name '{HUB_RULE}' -ErrorAction SilentlyContinue")).map(|_| ())
    }

    fn commands(&self, port: i64) -> Vec<String> {
        vec![format!("  {}", windows_rule(port))]
    }
}

/// This system's firewall for the hub's port, if cbb handles one.
pub(crate) fn system() -> Option<Box<dyn Firewall>> {
    if cfg!(windows) {
        Some(Box::new(WindowsFirewall))
    } else if cfg!(any(target_os = "linux", target_os = "freebsd")) {
        Some(Box::new(Script))
    } else {
        None
    }
}

/// Who may change the firewall.
#[cfg(not(windows))]
const ADMIN_NAME: &str = "root (sudo)";
#[cfg(windows)]
const ADMIN_NAME: &str = "an administrator";

/// What closes the hub's port that cbb opened.
#[cfg(not(windows))]
fn close_hint() -> String {
    format!("run sudo sh {} hub-close", firewall_script())
}
#[cfg(windows)]
fn close_hint() -> String {
    "run Remove-NetFirewallRule -Name cbb-hub in a PowerShell opened as administrator".into()
}

/// The UDP port a hub reached at its own address takes its clients on, or
/// 0.
pub(crate) fn hub_port_for(a: Option<&Away>) -> i64 {
    match a {
        Some(a) if a.hub && !a.endpoints.is_empty() => a.port,
        _ => 0,
    }
}

/// Opens the hub's port in the firewall or closes it, as the state a says;
/// mode is "ask", "yes" (-firewall yes) or "no". ask reads the answer.
pub(crate) fn sync(
    fw: &dyn Firewall,
    elevated: bool,
    a: Option<&Away>,
    mode: &str,
    out: &mut dyn Write,
    ask: &mut dyn FnMut() -> Option<String>,
) {
    let (want, have) = (hub_port_for(a), fw.opened());
    if want == have {
        return;
    }
    if have != 0 {
        if !elevated {
            let _ = writeln!(
                out,
                "The firewall still lets the internet reach UDP port {have}, which this device no longer needs; {}, or run cbb global again as {ADMIN_NAME}.",
                close_hint()
            );
        } else if let Err(e) = fw.close() {
            let _ = writeln!(out, "Closing UDP port {have} in {} failed: {}", fw.name(), e.message());
        }
    }
    if want == 0 || !fw.active() {
        return;
    }
    let _ = writeln!(out, "Firewall: the hub's clients reach this device from the internet. CBB requires this rule:");
    let _ = writeln!(
        out,
        "  1. Allow incoming UDP {want} from any address. Purpose: the group's WireGuard tunnel; it answers only the group's devices."
    );
    let mut yes = mode == "yes";
    let mut how = " (-firewall yes)";
    if mode == "ask" {
        how = "";
        if !elevated {
            let _ = writeln!(out, "Only {ADMIN_NAME} can add it.");
        } else {
            let _ = write!(
                out,
                "With Yes, CBB adds it now and removes it when this device stops being the hub.\nAdd this rule now? [y/N] "
            );
            let _ = out.flush();
            match ask() {
                Some(line) => yes = matches!(line.trim().to_lowercase().as_str(), "y" | "yes"),
                None => {
                    let _ = writeln!(out, "\nNo answer; taken as No.");
                }
            }
        }
    }
    if yes && elevated && fw.open(want).is_ok() {
        let _ = writeln!(out, "Added the rule above{how}.");
        let _ = writeln!(out, "A router in front of this device must forward UDP {want} to it as well.");
        return;
    }
    let _ = writeln!(
        out,
        "No firewall rule was added. The hub's clients reach it only while the firewall allows the rule above."
    );
    let cmds = fw.commands(want);
    if !cmds.is_empty() {
        let _ = writeln!(out, "To add it by hand, run:");
        for c in cmds {
            let _ = writeln!(out, "{c}");
        }
    }
    let _ = writeln!(out, "To let CBB add it, run cbb global hub again with -firewall yes as {ADMIN_NAME}.");
    let _ = writeln!(out, "A router in front of this device must forward UDP {want} to it as well.");
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Default)]
    struct Fake {
        opened: RefCell<i64>,
        fail: bool,
    }

    impl Firewall for Fake {
        fn name(&self) -> &'static str {
            "the firewall"
        }
        fn active(&self) -> bool {
            true
        }
        fn opened(&self) -> i64 {
            *self.opened.borrow()
        }
        fn open(&self, port: i64) -> Result<()> {
            if self.fail {
                return Err(Error::msg("denied"));
            }
            *self.opened.borrow_mut() = port;
            Ok(())
        }
        fn close(&self) -> Result<()> {
            *self.opened.borrow_mut() = 0;
            Ok(())
        }
        fn commands(&self, port: i64) -> Vec<String> {
            vec![format!("  open {port}")]
        }
    }

    fn hub(port: i64) -> Away {
        Away { hub: true, port, endpoints: vec![format!("203.0.113.7:{port}")], ..Default::default() }
    }

    #[test]
    fn opens_asks_and_closes() {
        let fw = Fake::default();
        let mut out = Vec::new();
        sync(&fw, true, Some(&hub(9000)), "ask", &mut out, &mut || Some("y\n".into()));
        let text = String::from_utf8(out).unwrap();
        assert_eq!(fw.opened(), 9000, "{text}");
        assert!(text.contains("Add this rule now? [y/N] ") && text.contains("Added the rule above.\n"), "{text}");
        // The same port again: nothing to do.
        let mut out = Vec::new();
        sync(&fw, true, Some(&hub(9000)), "ask", &mut out, &mut || panic!("asked again"));
        assert!(out.is_empty());
        // Behind a forwarder only: the port closes.
        let mut out = Vec::new();
        sync(&fw, true, Some(&Away { hub: true, port: 9000, ..Default::default() }), "ask", &mut out, &mut || None);
        assert_eq!(fw.opened(), 0);
        // No: the commands to add it by hand.
        let mut out = Vec::new();
        sync(&fw, true, Some(&hub(8764)), "ask", &mut out, &mut || Some("n\n".into()));
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("No firewall rule was added.") && text.contains("  open 8764\n"), "{text}");
        // -firewall yes without root: nothing added, and who may.
        let mut out = Vec::new();
        sync(&fw, false, Some(&hub(8764)), "yes", &mut out, &mut || panic!("asked"));
        let text = String::from_utf8(out).unwrap();
        assert!(fw.opened() == 0 && text.contains(&format!("as {ADMIN_NAME}.")), "{text}");
        // -firewall yes with root, but the firewall refuses.
        let fw = Fake { fail: true, ..Default::default() };
        let mut out = Vec::new();
        sync(&fw, true, Some(&hub(8764)), "yes", &mut out, &mut || panic!("asked"));
        assert!(String::from_utf8(out).unwrap().contains("No firewall rule was added."));
    }
}
