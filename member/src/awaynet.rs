// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the system lets the service reach, as the Go cbb's awaynet.go. On
//! Linux and Windows the installer lets the service reach only the home
//! network from outside the program: on Linux its systemd unit
//! (packaging/linux/cbb.service), on Windows an outbound rule of Windows
//! Firewall (packaging/windows/install.ps1). Sync away from home reaches the
//! group's own servers on the internet, its hub, forwarder and relay, so cbb
//! global lets the service reach those addresses and nothing else, and cbb
//! global off takes them away again. Both need root or an administrator. A
//! hub reached at its own address answers its clients wherever they are: on
//! Windows its UDP port is left open, and on Linux, whose unit cannot tell
//! ports apart, the unit allows every address and the program's own limit
//! holds.

use std::net::IpAddr;
use std::path::PathBuf;

use crate::control::Away;
use crate::error::{Error, Result};

/// What a user sees who changes sync away from home without root or an
/// administrator on a computer whose service is confined to the home
/// network.
#[cfg(not(windows))]
pub(crate) const NEED_ROOT: &str = "on this computer the system limits what the service may reach, and only root can change that: run the command again with sudo";
#[cfg(windows)]
pub(crate) const NEED_ROOT: &str = "on this computer the system limits what the service may reach, and only an administrator can change that: run the command again in a terminal opened as administrator";

/// The command that lets the service reach the group's servers.
#[cfg(not(windows))]
pub(crate) const ALLOW_HINT: &str = "run sudo cbb global allow";
#[cfg(windows)]
pub(crate) const ALLOW_HINT: &str = "run cbb global allow in a terminal opened as administrator";

/// What the system lets the service reach beyond the home network.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Grant {
    /// Sync away from home is on.
    pub on: bool,
    /// The group's hub, forwarder and relay, sorted.
    pub addrs: Vec<IpAddr>,
    /// A hub reached at its own address: its UDP port; 0 otherwise.
    pub hub_port: i64,
    /// 100.64.0.0/10 is left to the home network (CBB_HOME_CGNAT=1) in the
    /// Windows rule; on Linux the installer's own drop-in does it.
    pub cgnat: bool,
}

impl Grant {
    /// Whether two grants allow the same; without sync away from home the
    /// installer's rule is all there is, so off equals off.
    pub fn same(&self, o: &Grant) -> bool {
        if !self.on || !o.on {
            return self.on == o.on;
        }
        self.hub_port == o.hub_port && self.cgnat == o.cgnat && self.addrs == o.addrs
    }
}

impl std::fmt::Display for Grant {
    /// What the grant allows, for the user.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.on {
            return f.write_str("the home network only");
        }
        let mut parts: Vec<String> = self.addrs.iter().map(ToString::to_string).collect();
        if self.hub_port != 0 {
            parts.push(format!("any address on the hub's UDP port {}", self.hub_port));
        }
        if parts.is_empty() {
            return f.write_str("the home network only, as the group's servers are not known yet");
        }
        write!(f, "the home network and {}", parts.join(", "))
    }
}

/// The grant the service's state asks for.
pub(crate) fn grant_for(a: Option<&Away>, cgnat: bool) -> Grant {
    let Some(a) = a else { return Grant::default() };
    let mut g = Grant { on: true, cgnat, ..Default::default() };
    for s in &a.allow {
        if let Ok(ad) = s.parse::<IpAddr>().map(|a| a.to_canonical())
            && !g.addrs.contains(&ad)
        {
            g.addrs.push(ad);
        }
    }
    g.addrs.sort();
    if a.hub && !a.endpoints.is_empty() {
        g.hub_port = a.port;
    }
    g
}

/// One system's way of keeping the service on the home network and the
/// group's servers.
pub(crate) trait Limit {
    /// The installer set the limit up.
    fn present(&self) -> bool;
    /// What it lets the service reach now.
    fn granted(&self) -> Grant;
    /// Lets the service reach g.
    fn set(&self, g: &Grant) -> Result<()>;
    /// Changing it restarts the service.
    fn restarts(&self) -> bool;
    /// 100.64.0.0/10 is the home network to the service.
    fn home_cgnat(&self) -> bool {
        false
    }
}

/// This computer's limit and whether this process may change it.
pub(crate) struct Net {
    pub limit: Option<Box<dyn Limit>>,
    pub elevated: bool,
}

impl Net {
    /// The limit of this system, if it has one.
    pub fn system() -> Net {
        let limit: Option<Box<dyn Limit>> = if cfg!(windows) {
            Some(Box::new(Windows { powershell: Box::new(crate::hubport::powershell) }))
        } else if cfg!(target_os = "linux") {
            Some(Box::new(Systemd::system()))
        } else {
            None
        };
        Net { limit, elevated: crate::sys::is_root() }
    }

    /// Whether this computer's service is confined by its installer.
    pub fn confined(&self) -> bool {
        self.limit.as_ref().is_some_and(|l| l.present())
    }

    /// Whether the service counts 100.64.0.0/10 as the home network.
    pub fn home_cgnat(&self) -> bool {
        self.limit.as_ref().is_some_and(|l| l.home_cgnat())
    }

    /// The grant the service's state asks for, on this system.
    pub fn grant_for(&self, a: Option<&Away>) -> Grant {
        grant_for(a, self.home_cgnat())
    }

    /// What the system lets the service reach now; without a limit,
    /// whatever the service asks for.
    pub fn granted(&self, want: &Grant) -> Grant {
        match &self.limit {
            Some(l) if l.present() => l.granted(),
            _ => want.clone(),
        }
    }

    /// Fails before anything changes when this command will have to change
    /// the limit but may not.
    pub fn check(&self) -> Result<()> {
        if !self.confined() || self.elevated { Ok(()) } else { Err(Error::msg(NEED_ROOT)) }
    }

    /// Lets the service reach g, and reports whether that changed and
    /// whether the service restarted for it.
    pub fn set(&self, g: &Grant) -> Result<(bool, bool)> {
        let Some(l) = self.limit.as_ref().filter(|l| l.present()) else { return Ok((false, false)) };
        if l.granted().same(g) {
            return Ok((false, false));
        }
        if !self.elevated {
            return Err(Error::msg(NEED_ROOT));
        }
        l.set(g)?;
        Ok((true, l.restarts()))
    }
}

/// Runs systemctl with its arguments.
pub(crate) type Systemctl = dyn Fn(&[&str]) -> Result<()>;

/// Runs a PowerShell script and returns its output.
pub(crate) type PowerShell = dyn Fn(&str) -> Result<String>;

/// Linux: a systemd drop-in that adds the group's servers to the unit's
/// IPAddressAllow, and a restart, since systemd applies it when the
/// service starts.
pub(crate) struct Systemd {
    pub unit: PathBuf,
    pub drop_in: PathBuf,
    pub systemctl: Box<Systemctl>,
}

impl Systemd {
    fn system() -> Systemd {
        Systemd {
            unit: "/etc/systemd/system/cbb.service".into(),
            drop_in: "/etc/systemd/system/cbb.service.d/away.conf".into(),
            systemctl: Box::new(|args| run("systemctl", args)),
        }
    }
}

/// Runs a program and fails with its output.
fn run(name: &str, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(name)
        .args(args)
        .output()
        .map_err(|e| Error::msg(format!("{name} {}: {e}", args.join(" "))))?;
    if out.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&[out.stdout, out.stderr].concat()).trim().to_string();
    Err(Error::msg(format!("{name} {}: {}: {text}", args.join(" "), out.status)))
}

/// The drop-in for g.
pub(crate) fn drop_in_text(g: &Grant) -> String {
    let mut b = String::from(
        "# Written by cbb global; cbb global off removes it, and cbb global allow
# writes it again when the group's servers change. With sync away from home
# on, the service may reach the group's hub, forwarder and relay beyond the
# home network, and nothing else.
",
    );
    if g.hub_port != 0 {
        b += &format!(
            "# This device is a hub reached at its own address, which answers its
# clients wherever they are; systemd cannot allow one port only, so the
# service's own limit keeps every other connection to the addresses above.
# hub-port {}
",
            g.hub_port
        );
    }
    b += "[Service]\n";
    if g.hub_port != 0 {
        b += "IPAddressAllow=any\n";
    } else if !g.addrs.is_empty() {
        let list: Vec<String> = g.addrs.iter().map(ToString::to_string).collect();
        b += &format!("IPAddressAllow={}\n", list.join(" "));
    }
    b
}

/// Reads a grant back from the drop-in.
pub(crate) fn parse_drop_in(text: &str) -> Grant {
    let mut g = Grant { on: true, ..Default::default() };
    for line in text.lines().map(str::trim) {
        if let Some(v) = line.strip_prefix("# hub-port ") {
            g.hub_port = v.parse().unwrap_or(0);
        }
        if let Some(v) = line.strip_prefix("IPAddressAllow=") {
            g.addrs.extend(v.split_whitespace().filter_map(|f| f.parse::<IpAddr>().ok()));
        }
    }
    g
}

impl Limit for Systemd {
    fn present(&self) -> bool {
        self.unit.exists()
    }

    fn granted(&self) -> Grant {
        std::fs::read_to_string(&self.drop_in).map(|t| parse_drop_in(&t)).unwrap_or_default()
    }

    fn set(&self, g: &Grant) -> Result<()> {
        let fail = |e: std::io::Error| Error::msg(format!("{}: {e}", self.drop_in.display()));
        if g.on {
            if let Some(dir) = self.drop_in.parent() {
                std::fs::create_dir_all(dir).map_err(fail)?;
            }
            // Whole or not at all: systemd never reads half a drop-in.
            crate::files::write_atomic(&self.drop_in, drop_in_text(g).as_bytes(), 0o644)
                .map_err(|e| Error::msg(format!("{}: {e}", self.drop_in.display())))?;
        } else if let Err(e) = std::fs::remove_file(&self.drop_in)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(fail(e));
        }
        (self.systemctl)(&["daemon-reload"])?;
        (self.systemctl)(&["restart", "cbb.service"])
    }

    fn restarts(&self) -> bool {
        true
    }
}

/// The installer's outbound rule on Windows.
pub(crate) const FIREWALL_RULE: &str = "cbb-home-only";
const SERVICE_KEY: &str = r"HKLM:\SYSTEM\CurrentControlSet\Services\cbb";

/// Every address outside the home network, as the installer's rule lists
/// it: all but loopback, private IPv4, link-local, multicast and broadcast,
/// and unique-local, link-local and multicast IPv6.
pub(crate) const OUTSIDE: [(&str, &str); 9] = [
    ("0.0.0.0", "9.255.255.255"),
    ("11.0.0.0", "126.255.255.255"),
    ("128.0.0.0", "169.253.255.255"),
    ("169.255.0.0", "172.15.255.255"),
    ("172.32.0.0", "192.167.255.255"),
    ("192.169.0.0", "223.255.255.255"),
    ("::2", "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ("fe00::", "fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ("fec0::", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
];

/// The address after or before a, in its own family.
fn step(a: IpAddr, up: bool) -> IpAddr {
    match a {
        IpAddr::V4(v) => {
            let n = u32::from(v);
            IpAddr::V4((if up { n.wrapping_add(1) } else { n.wrapping_sub(1) }).into())
        }
        IpAddr::V6(v) => {
            let n = u128::from(v);
            IpAddr::V6((if up { n.wrapping_add(1) } else { n.wrapping_sub(1) }).into())
        }
    }
}

/// The ranges of OUTSIDE without the addresses allowed, and with cgnat
/// without 100.64.0.0/10.
pub(crate) fn blocked(allowed: &[IpAddr], cgnat: bool) -> Vec<String> {
    let ip = |s: &str| s.parse::<IpAddr>().expect("a fixed address");
    let mut spans: Vec<(IpAddr, IpAddr)> = OUTSIDE.iter().map(|(lo, hi)| (ip(lo), ip(hi))).collect();
    let mut holes: Vec<(IpAddr, IpAddr)> = allowed.iter().map(|a| (a.to_canonical(), a.to_canonical())).collect();
    if cgnat {
        holes.push((ip("100.64.0.0"), ip("100.127.255.255")));
    }
    for (hlo, hhi) in holes {
        // Addresses of the two families never overlap: IpAddr orders every
        // IPv4 address before every IPv6 one.
        if let Some(i) = spans.iter().position(|&(lo, hi)| !(hhi < lo || hi < hlo)) {
            let (lo, hi) = spans[i];
            let mut parts = Vec::new();
            if lo < hlo {
                parts.push((lo, step(hlo, false)));
            }
            if hhi < hi {
                parts.push((step(hhi, true), hi));
            }
            spans.splice(i..=i, parts);
        }
    }
    spans.iter().map(|(lo, hi)| if lo == hi { lo.to_string() } else { format!("{lo}-{hi}") }).collect()
}

/// The script that writes the rules for g and keeps g in the service's
/// key.
pub(crate) fn windows_script(g: &Grant) -> String {
    let quote = |ss: &[String]| {
        let q: Vec<String> = ss.iter().map(|s| format!("'{s}'")).collect();
        format!("@({})", q.join(", "))
    };
    let block = quote(&blocked(&g.addrs, g.cgnat));
    let mut b = String::from("$ErrorActionPreference = 'Stop'\n");
    b += &format!("$prog = (Get-NetFirewallRule -Name '{FIREWALL_RULE}' | Get-NetFirewallApplicationFilter).Program\n");
    b += "Get-NetFirewallRule -Group 'cbb' | Where-Object { [string]$_.Direction -eq 'Outbound' } | Remove-NetFirewallRule\n";
    let common = "-Group 'cbb' -Direction Outbound -Action Block -Program $prog -Service 'cbb' -Profile Any";
    // PowerShell doubles a quote inside single quotes.
    let desc = "The CBB service reaches only the home network and its group''s servers; cbb global changes this rule.";
    if g.hub_port == 0 {
        b += &format!(
            "New-NetFirewallRule -Name '{FIREWALL_RULE}' -DisplayName 'cbb: only the home network' {common} -RemoteAddress {block} -Description '{desc}' | Out-Null\n"
        );
    } else {
        let mut ports = Vec::new();
        if g.hub_port > 1 {
            ports.push(format!("1-{}", g.hub_port - 1));
        }
        if g.hub_port < 65535 {
            ports.push(format!("{}-65535", g.hub_port + 1));
        }
        b += &format!(
            "New-NetFirewallRule -Name '{FIREWALL_RULE}' -DisplayName 'cbb: only the home network' {common} -Protocol TCP -RemoteAddress {block} -Description '{desc}' | Out-Null\n"
        );
        b += &format!(
            "New-NetFirewallRule -Name '{FIREWALL_RULE}-udp' -DisplayName 'cbb: only the home network, UDP but the hub''s port' {common} -Protocol UDP -LocalPort {} -RemoteAddress {block} -Description '{desc}' | Out-Null\n",
            quote(&ports)
        );
    }
    if g.on {
        let mut v = std::iter::once("on".to_string())
            .chain(g.addrs.iter().map(ToString::to_string))
            .collect::<Vec<_>>()
            .join(" ");
        if g.hub_port != 0 {
            v += &format!(" hub-port:{}", g.hub_port);
        }
        if g.cgnat {
            v += " cgnat";
        }
        b += &format!(
            "New-ItemProperty -Path '{SERVICE_KEY}' -Name AwayAllow -PropertyType String -Value '{v}' -Force | Out-Null\n"
        );
    } else {
        b += &format!("Remove-ItemProperty -Path '{SERVICE_KEY}' -Name AwayAllow -ErrorAction SilentlyContinue\n");
    }
    b
}

/// Reads a grant back from the service's key.
pub(crate) fn parse_away_allow(v: &str) -> Grant {
    let mut f = v.split_whitespace();
    if f.next() != Some("on") {
        return Grant::default();
    }
    let mut g = Grant { on: true, ..Default::default() };
    for s in f {
        if let Some(p) = s.strip_prefix("hub-port:") {
            g.hub_port = p.parse().unwrap_or(0);
        } else if s == "cgnat" {
            g.cgnat = true;
        } else if let Ok(a) = s.parse::<IpAddr>() {
            g.addrs.push(a);
        }
    }
    g
}

/// Windows: an outbound rule of Windows Firewall blocks the service from
/// every address outside the home network but the group's servers; for a
/// hub reached at its own address it blocks TCP, and a second rule blocks
/// UDP on every local port but the hub's. A change applies at once, so
/// nothing restarts. What the rules allow is kept beside them in the
/// service's registry key (AwayAllow), so a reinstall keeps it.
pub(crate) struct Windows {
    pub powershell: Box<PowerShell>,
}

impl Limit for Windows {
    fn present(&self) -> bool {
        // A failed lookup counts as a limit, so that a change asks for an
        // administrator rather than doing nothing.
        (self.powershell)(&format!(
            "if (Get-NetFirewallRule -Name '{FIREWALL_RULE}' -ErrorAction SilentlyContinue) {{ 'yes' }} else {{ 'no' }}"
        ))
        .map_or(true, |out| out == "yes")
    }

    fn granted(&self) -> Grant {
        (self.powershell)(&format!(
            "[string](Get-ItemProperty -Path '{SERVICE_KEY}' -Name AwayAllow -ErrorAction SilentlyContinue).AwayAllow"
        ))
        .map(|v| parse_away_allow(&v))
        .unwrap_or_default()
    }

    fn set(&self, g: &Grant) -> Result<()> {
        // Off too, the rule leaves 100.64.0.0/10 to the home network when
        // the service counts it as home.
        let g = Grant { cgnat: self.home_cgnat(), ..g.clone() };
        (self.powershell)(&windows_script(&g)).map(|_| ())
    }

    fn restarts(&self) -> bool {
        false
    }

    /// As install.ps1 -HomeCgnat on keeps it in the service's environment.
    fn home_cgnat(&self) -> bool {
        (self.powershell)(&format!(
            "if ((Get-ItemProperty -Path '{SERVICE_KEY}' -Name Environment -ErrorAction SilentlyContinue).Environment -contains 'CBB_HOME_CGNAT=1') {{ 'yes' }} else {{ 'no' }}"
        ))
        .is_ok_and(|out| out == "yes")
    }
}

/// What status says of the system's limit beside sync away from home: what
/// it still allows with sync away from home off, or that it no longer fits
/// the group's servers.
pub(crate) fn limit_note(net: &Net, a: Option<&Away>) -> String {
    if !net.confined() {
        return String::new();
    }
    match a {
        None => {
            let have = net.granted(&Grant::default());
            if have.on {
                format!("This computer still lets the service reach {have}: {ALLOW_HINT}.\n")
            } else {
                String::new()
            }
        }
        Some(a) => {
            let want = net.grant_for(Some(a));
            let have = net.granted(&want);
            if have.same(&want) {
                String::new()
            } else {
                format!(
                    "This computer lets the service reach {have}, but the group's servers are now {want}: {ALLOW_HINT}.\n"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn hub_addr() -> IpAddr {
        ip("203.0.113.7")
    }

    fn fwd_addr() -> IpAddr {
        ip("198.51.100.9")
    }

    #[test]
    fn grant_from_status() {
        assert!(!grant_for(None, false).on);
        let a = Away {
            hub_device: "hub".into(),
            endpoints: vec!["203.0.113.7:8764".into()],
            allow: vec!["203.0.113.7".into(), "198.51.100.9".into(), "203.0.113.7".into()],
            ..Default::default()
        };
        let want = Grant { on: true, addrs: vec![fwd_addr(), hub_addr()], ..Default::default() };
        assert!(grant_for(Some(&a), false).same(&want));
        let a = Away {
            hub: true,
            port: 9000,
            endpoints: vec!["203.0.113.7:9000".into()],
            allow: vec!["198.51.100.9".into()],
            ..Default::default()
        };
        let want = Grant { on: true, addrs: vec![fwd_addr()], hub_port: 9000, ..Default::default() };
        assert!(grant_for(Some(&a), false).same(&want));
        // A hub reached only through its forwarder answers nobody else.
        let a = Away { hub: true, port: 8764, allow: vec!["198.51.100.9".into()], ..Default::default() };
        assert_eq!(grant_for(Some(&a), false).hub_port, 0);
    }

    /// A unit in a temporary folder, its systemctl calls recorded.
    fn fake_unit(root: bool) -> (Net, PathBuf, Rc<RefCell<Vec<String>>>) {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("cbb-awaynet-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cbb.service"), "[Service]\n").unwrap();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let c = calls.clone();
        let drop_in = dir.join("cbb.service.d").join("away.conf");
        let limit = Systemd {
            unit: dir.join("cbb.service"),
            drop_in: drop_in.clone(),
            systemctl: Box::new(move |args| {
                c.borrow_mut().push(args.join(" "));
                Ok(())
            }),
        };
        (Net { limit: Some(Box::new(limit)), elevated: root }, drop_in, calls)
    }

    #[test]
    fn systemd_drop_in() {
        let (net, drop_in, calls) = fake_unit(true);
        net.check().unwrap();
        let client = Grant { on: true, addrs: vec![fwd_addr(), hub_addr()], ..Default::default() };
        assert_eq!(net.set(&client).unwrap(), (true, true));
        let text = std::fs::read_to_string(&drop_in).unwrap();
        assert!(text.contains("\nIPAddressAllow=198.51.100.9 203.0.113.7\n"), "{text}");
        assert_eq!(*calls.borrow(), ["daemon-reload", "restart cbb.service"]);
        assert!(net.granted(&Grant::default()).same(&client));
        assert_eq!(net.set(&client).unwrap(), (false, false));
        // Before the hub's offer: on, and nothing beyond the home network.
        net.set(&Grant { on: true, ..Default::default() }).unwrap();
        assert!(!std::fs::read_to_string(&drop_in).unwrap().contains("IPAddressAllow"));
        // A hub at its own address: systemd cannot allow one port only.
        let hub = Grant { on: true, addrs: vec![fwd_addr()], hub_port: 9000, ..Default::default() };
        net.set(&hub).unwrap();
        assert!(std::fs::read_to_string(&drop_in).unwrap().contains("\nIPAddressAllow=any\n"));
        let back = net.granted(&Grant::default());
        assert!(back.on && back.hub_port == 9000);
        assert_eq!(net.set(&Grant::default()).unwrap(), (true, true));
        assert!(!drop_in.exists());
        // A drop-in that is not this grant's is replaced.
        std::fs::write(&drop_in, "[Service]\nIPAddressAllow=any\n").unwrap();
        assert!(net.set(&client).unwrap().0);
        assert!(net.granted(&Grant::default()).same(&client));
        net.set(&Grant::default()).unwrap();
        assert_eq!(calls.borrow().len(), 12);
        let _ = std::fs::remove_dir_all(drop_in.parent().unwrap().parent().unwrap());
    }

    /// A drop-in write cut at every step leaves the drop-in before it.
    #[test]
    fn a_drop_in_cut_short_is_the_one_before() {
        use crate::files::faults::{self, How};
        let (net, drop_in, _) = fake_unit(true);
        let client = Grant { on: true, addrs: vec![fwd_addr(), hub_addr()], ..Default::default() };
        net.set(&client).unwrap();
        let before = std::fs::read_to_string(&drop_in).unwrap();
        let other = Grant { on: true, ..Default::default() };
        for step in 0..drop_in_text(&other).len() + 3 {
            for how in [How::Dies, How::Fails] {
                faults::at(step, how);
                assert!(net.set(&other).is_err(), "step {step}");
                assert_eq!(std::fs::read_to_string(&drop_in).unwrap(), before, "step {step} ({how:?})");
            }
        }
        net.set(&other).unwrap();
        assert!(!std::fs::read_to_string(&drop_in).unwrap().contains("IPAddressAllow"));
        let _ = std::fs::remove_dir_all(drop_in.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn systemd_needs_root() {
        let (net, drop_in, calls) = fake_unit(false);
        assert_eq!(net.check().unwrap_err().message(), NEED_ROOT);
        assert_eq!(net.set(&Grant::default()).unwrap(), (false, false));
        assert_eq!(net.set(&Grant { on: true, ..Default::default() }).unwrap_err().message(), NEED_ROOT);
        assert!(!drop_in.exists() && calls.borrow().is_empty());
        // Without the installer's unit, nothing is confined.
        let net = Net {
            limit: Some(Box::new(Systemd {
                unit: drop_in.with_file_name("missing.service"),
                drop_in: drop_in.clone(),
                systemctl: Box::new(|_| panic!("no systemctl")),
            })),
            elevated: false,
        };
        net.check().unwrap();
        assert_eq!(net.set(&Grant { on: true, ..Default::default() }).unwrap(), (false, false));
        let none = Net { limit: None, elevated: false };
        assert!(!none.confined() && none.check().is_ok() && none.granted(&Grant { on: true, ..Default::default() }).on);
        let _ = std::fs::remove_dir_all(drop_in.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn blocked_ranges() {
        let got = blocked(&[], false);
        assert_eq!(got.len(), OUTSIDE.len());
        assert_eq!(got[0], "0.0.0.0-9.255.255.255");
        let got = blocked(&[hub_addr(), ip("2001:db8::1"), ip("11.0.0.0")], false);
        for want in [
            "192.169.0.0-203.0.113.6",
            "203.0.113.8-223.255.255.255",
            "::2-2001:db8::",
            "2001:db8::2-fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "11.0.0.1-126.255.255.255",
        ] {
            assert!(got.iter().any(|r| r == want), "blocked lacks {want}: {got:?}");
        }
        assert_eq!(got.len(), OUTSIDE.len() + 2, "{got:?}");
        // CBB_HOME_CGNAT=1: 100.64.0.0/10 is home, its neighbours are not.
        let got = blocked(&[hub_addr()], true);
        for want in ["11.0.0.0-100.63.255.255", "100.128.0.0-126.255.255.255"] {
            assert!(got.iter().any(|r| r == want), "with cgnat, blocked lacks {want}: {got:?}");
        }
        assert_eq!(got.len(), OUTSIDE.len() + 2);
    }

    /// On Windows the firewall rules are the limit, and the service's key
    /// keeps what they allow.
    #[test]
    fn windows_rules() {
        #[derive(Default)]
        struct Fake {
            rule: String,
            kept: String,
            cgnat: bool,
            scripts: Vec<String>,
        }
        let fake = Rc::new(RefCell::new(Fake { rule: "no".into(), ..Default::default() }));
        let f = fake.clone();
        let ps = move |script: &str| -> Result<String> {
            let mut f = f.borrow_mut();
            const KEPT: &str = "-Name AwayAllow -PropertyType String -Value '";
            if script.contains("New-NetFirewallRule") {
                f.scripts.push(script.to_string());
                f.kept = script
                    .find(KEPT)
                    .map(|i| script[i + KEPT.len()..].split('\'').next().unwrap().to_string())
                    .unwrap_or_default();
                return Ok(String::new());
            }
            if script.contains("CBB_HOME_CGNAT") {
                return Ok(if f.cgnat { "yes" } else { "no" }.into());
            }
            if f.rule == "error" {
                return Err(Error::msg("access denied"));
            }
            if script.contains("AwayAllow") {
                return Ok(f.kept.clone());
            }
            Ok(f.rule.clone())
        };
        let mut net = Net { limit: Some(Box::new(Windows { powershell: Box::new(ps) })), elevated: false };
        assert!(!net.confined() && net.check().is_ok());
        fake.borrow_mut().rule = "yes".into();
        assert!(net.check().is_err());
        fake.borrow_mut().rule = "error".into();
        assert!(net.check().is_err(), "a lookup that fails asks for an administrator");
        fake.borrow_mut().rule = "yes".into();
        net.elevated = true;
        let client = Grant { on: true, addrs: vec![fwd_addr(), hub_addr()], ..Default::default() };
        assert_eq!(net.set(&client).unwrap(), (true, false));
        assert!(net.granted(&Grant::default()).same(&client));
        let s = fake.borrow().scripts[0].clone();
        for line in s.lines() {
            assert_eq!(line.matches('\'').count() % 2, 0, "an unmatched quote in PowerShell: {line}");
        }
        assert!(
            s.contains("'203.0.113.8-223.255.255.255'") && !s.contains("-Protocol") && !s.contains("cbb-home-only-udp")
        );
        let hub = Grant { on: true, addrs: vec![fwd_addr()], hub_port: 8764, ..Default::default() };
        net.set(&hub).unwrap();
        assert!(net.granted(&Grant::default()).same(&hub));
        let s = fake.borrow().scripts[1].clone();
        assert!(s.contains("-Protocol TCP") && s.contains("-LocalPort @('1-8763', '8765-65535')"), "{s}");
        assert!(net.set(&Grant::default()).unwrap().0);
        assert!(!net.granted(&Grant::default()).on);
        let s = fake.borrow().scripts[2].clone();
        assert!(s.contains("Remove-ItemProperty") && s.contains("'0.0.0.0-9.255.255.255'"));
        // CBB_HOME_CGNAT=1 in the service's environment: the rule leaves
        // 100.64.0.0/10 to it, AwayAllow says so, and a grant without it
        // differs, so cbb global allow writes the rule again.
        fake.borrow_mut().cgnat = true;
        let cg = net
            .grant_for(Some(&Away { allow: vec!["198.51.100.9".into(), "203.0.113.7".into()], ..Default::default() }));
        assert!(cg.cgnat && !cg.same(&client));
        net.set(&cg).unwrap();
        assert!(net.granted(&Grant::default()).same(&cg) && fake.borrow().kept.ends_with(" cgnat"));
        let s = fake.borrow().scripts[3].clone();
        assert!(s.contains("'100.128.0.0-126.255.255.255'") && !s.contains("'11.0.0.0-126.255.255.255'"));
        net.set(&Grant::default()).unwrap();
        assert!(fake.borrow().scripts[4].contains("'11.0.0.0-100.63.255.255'"));
    }

    #[test]
    fn grant_text() {
        assert_eq!(Grant::default().to_string(), "the home network only");
        assert_eq!(
            Grant { on: true, ..Default::default() }.to_string(),
            "the home network only, as the group's servers are not known yet"
        );
        let g = Grant { on: true, addrs: vec![fwd_addr()], hub_port: 9000, ..Default::default() };
        assert_eq!(g.to_string(), "the home network and 198.51.100.9, any address on the hub's UDP port 9000");
    }
}
