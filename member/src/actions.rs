// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The quick actions (docs/design.md, "Quick actions"), as the full
//! member's internal/actions, in the same files: the presets and the user's
//! own actions. Each is off until the device's own user turns it on there;
//! the checks of the signer, the polkit rule that lets the service ask
//! logind, and the log of the last ones.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};
use crate::files;

/// The presets, in the order the apps show them: lock the screen, sleep,
/// reboot, shut down, cancel a reboot or shutdown that is pending, restart
/// the service, and switch the layout the computer's Bluetooth keyboard
/// types in to the next one.
pub const LOCK: &str = "lock";
pub const SLEEP: &str = "sleep";
pub const REBOOT: &str = "reboot";
pub const SHUTDOWN: &str = "shutdown";
pub const CANCEL: &str = "cancel-shutdown";
pub const RESTART: &str = "restart";
pub const LAYOUT: &str = "keyboard-layout";
pub const PRESETS: &[&str] = &[LOCK, SLEEP, REBOOT, SHUTDOWN, CANCEL, RESTART, LAYOUT];

/// How many actions of their own a device's user may add.
pub const MAX_OWN: usize = 32;

/// The kinds of signers an action may allow: the group's root, an admin
/// phone, an admin computer, a watch with an admin key of its own.
pub const KINDS: &[&str] = &["root", "phone", "computer", "watch"];

/// One action as this device's user set it: on or off, the kinds of admins
/// that may run it (every kind when none), and whether a signer whose key
/// is in a file may reboot.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub name: String,
    #[serde(default)]
    pub on: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub by: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub any_key: bool,
    /// The program and its arguments of the user's own action, which the
    /// agent runs as the user signed in; empty for a preset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
}

/// This device's actions.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Action>,
}

const SETTINGS_FILE: &str = "actions.json";
pub const LOG_FILE: &str = "actions-log.json";
/// How many actions the log keeps.
pub const LOG_SIZE: usize = 100;
/// How long a reboot or shutdown waits, which cancel-shutdown stops, in
/// minutes.
const DELAY_MINUTES: &str = "+1";

impl Settings {
    /// The action name as its user set it: off when they never did.
    pub fn get(&self, name: &str) -> Action {
        self.actions
            .iter()
            .find(|a| a.name == name)
            .cloned()
            .unwrap_or_else(|| Action { name: name.into(), ..Default::default() })
    }

    /// Whether this device has the action name: a preset, or one of its
    /// user's own.
    pub fn has(&self, name: &str) -> bool {
        PRESETS.contains(&name) || self.actions.iter().any(|a| a.name == name)
    }

    /// The user's own actions.
    pub fn own(&self) -> Vec<Action> {
        self.actions.iter().filter(|a| !a.command.is_empty()).cloned().collect()
    }

    /// Takes the user's own action name away.
    pub fn remove(&mut self, name: &str) -> bool {
        let n = self.actions.len();
        self.actions.retain(|a| a.name != name || a.command.is_empty());
        self.actions.len() != n
    }

    /// Sets an action, keeping the presets in their order.
    pub fn set(&mut self, a: Action) {
        self.actions.retain(|x| x.name != a.name);
        self.actions.push(a);
        self.actions.sort_by_key(|a| PRESETS.iter().position(|p| *p == a.name).unwrap_or(PRESETS.len()));
    }

    /// Turns every action off; who may run them stays for the next time.
    pub fn all_off(&mut self) {
        for a in &mut self.actions {
            a.on = false;
        }
    }

    /// The actions that are on.
    pub fn on(&self) -> Vec<String> {
        self.actions.iter().filter(|a| a.on).map(|a| a.name.clone()).collect()
    }

    /// Every preset as it stands, then the user's own, for cbb action.
    pub fn all(&self) -> Vec<Action> {
        PRESETS.iter().map(|p| self.get(p)).chain(self.own()).collect()
    }
}

/// Reads the settings from dir: all off when there are none.
pub fn load(dir: &Path) -> Result<Settings> {
    match std::fs::read(dir.join(SETTINGS_FILE)) {
        Ok(b) => serde_json::from_slice(&b).context(SETTINGS_FILE),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(e) => Err(Error::with(format!("cannot read {}", dir.join(SETTINGS_FILE).display()), e)),
    }
}

/// Writes the settings to dir.
pub fn save(dir: &Path, s: &Settings) -> Result<()> {
    let mut b = serde_json::to_vec_pretty(s).context("cannot encode the quick actions")?;
    b.push(b'\n');
    files::write_atomic(&dir.join(SETTINGS_FILE), &b, 0o600)
}

/// Reads a list of signer kinds, such as "phone,computer".
pub fn parse_kinds(s: &str) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for k in s.split(',').map(str::trim).filter(|k| !k.is_empty()) {
        if !KINDS.contains(&k) {
            return Err(Error::msg(format!("{k:?} is not a kind of admin: root, phone, computer or watch")));
        }
        if !out.iter().any(|x| x == k) {
            out.push(k.to_string());
        }
    }
    Ok(out)
}

/// Whether only admins with keys in hardware run the action name until
/// its user says otherwise: reboot and shut down, which a stolen key in a
/// file must not do (D-71).
pub fn hardware_by_default(name: &str) -> bool {
    name == REBOOT || name == SHUTDOWN
}

/// Why name and command cannot be an action of the user's own, or None: a
/// name that is not a preset, and a program by its full path, so that
/// nothing in PATH or a shell decides what runs (Go's CheckOwn).
pub fn check_own(name: &str, command: &[String]) -> Option<String> {
    if !cbb_core::command::valid_action_name(name) {
        return Some(format!(
            "{name:?} is not an action's name: 1 to {} of a-z, 0-9 and -, starting with a letter",
            cbb_core::command::MAX_ACTION_NAME
        ));
    }
    if PRESETS.contains(&name) {
        return Some(format!("{name} is a preset; give your own action another name"));
    }
    let Some(prog) = command.first() else {
        return Some("an action of your own needs a command: cbb action add NAME -- PROGRAM ARGS".into());
    };
    if !Path::new(prog).is_absolute() {
        return Some(format!("give the program by its full path, not {prog:?}"));
    }
    None
}

/// The admin that signed an action command, as the group's records show it
/// (Records::command_signer).
#[derive(Default, Debug, Clone)]
pub struct Signer {
    /// The group's root key signed it.
    pub root: bool,
    /// The device's role, phone, member or watch; empty when no record names it.
    pub role: String,
    /// Where its keys live; empty when unknown.
    pub store: String,
}

impl Signer {
    /// The kinds of signers it is: the root, and the kind of its device.
    pub fn kinds(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.root {
            out.push("root");
        }
        match self.role.as_str() {
            "phone" => out.push("phone"),
            "member" => out.push("computer"),
            "watch" => out.push("watch"),
            _ => {}
        }
        out
    }

    pub fn in_hardware(&self) -> bool {
        self.store == "hardware" || self.store == "proven"
    }
}

/// Why the action a, as this device's user set it, may not run for the
/// signer s, or None, with the full member's words.
pub fn check(a: &Action, s: &Signer) -> Option<String> {
    let n = &a.name;
    if !a.on {
        return Some(format!(
            "the action {n} is off on this device; its user turns it on there with {}cbb action enable {n}",
            crate::rootless::sudo()
        ));
    }
    if !a.by.is_empty() && !s.kinds().iter().any(|k| a.by.iter().any(|b| b == k)) {
        return Some(format!("this device runs {n} only for {}", a.by.join(", ")));
    }
    if hardware_by_default(n) && !a.any_key && !s.in_hardware() {
        return Some(format!(
            "this device runs {n} only for admins whose keys are in hardware, and the sender's key is in a file; its user allows that with {}cbb action enable {n} -any-key",
            crate::rootless::sudo()
        ));
    }
    None
}

/// How an action that passed the checks did not happen.
#[derive(Debug)]
pub enum Failure {
    /// The device will not: its user fixes it there. The reason goes to
    /// the sender as it is.
    Refused(String),
    Failed(Error),
}

/// Runs a preset of the system through logind's tools, which ask logind
/// over the system bus: loginctl locks the sessions, systemctl suspends,
/// shutdown(8) schedules a reboot or shutdown or cancels it; the polkit rule
/// of grant lets the service's user do exactly the presets that are on.
/// Restart and the keyboard's layout are the service's own.
pub fn run(name: &str) -> std::result::Result<(), Failure> {
    let (tool, args): (&str, &[&str]) = match name {
        LOCK => ("loginctl", &["lock-sessions"]),
        SLEEP => ("systemctl", &["suspend"]),
        REBOOT => ("shutdown", &["-r", DELAY_MINUTES]),
        SHUTDOWN => ("shutdown", &["-P", DELAY_MINUTES]),
        CANCEL => ("shutdown", &["-c"]),
        n => return Err(Failure::Refused(format!("this device has no action {n:?}"))),
    };
    let bin = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .into_iter()
        .map(|d| format!("{d}/{tool}"))
        .find(|p| Path::new(p).exists());
    let Some(bin) = bin else {
        return Err(Failure::Failed(Error::msg(format!(
            "this system has no {tool}, so CBB cannot {name} it; the action needs systemd's logind"
        ))));
    };
    let out = Command::new(&bin)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| Failure::Failed(Error::with(format!("cannot run {bin}"), e)))?;
    if out.status.success() {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if denied(&said) {
        return Err(Failure::Refused(format!(
            "this device's user has not given CBB the right to {name}; they run sudo cbb action enable {name} there"
        )));
    }
    Err(Failure::Failed(Error::msg(format!("{bin} {}: {} {said}", args.join(" "), out.status))))
}

/// Whether systemctl's words say that polkit said no.
fn denied(said: &str) -> bool {
    ["Access denied", "Interactive authentication required", "not authorized"].iter().any(|w| said.contains(w))
}

/// The service's user, which the polkit rule lets act.
const SERVICE_USER: &str = "cbb";

/// The polkit actions of each preset that needs one: a reboot or shutdown
/// while someone is logged in needs the multiple-sessions right too, and
/// cancelling one needs the right that scheduled it.
fn rights_of(name: &str) -> &'static [&'static str] {
    match name {
        LOCK => &["org.freedesktop.login1.lock-sessions"],
        SLEEP => &["org.freedesktop.login1.suspend", "org.freedesktop.login1.suspend-multiple-sessions"],
        REBOOT => &["org.freedesktop.login1.reboot", "org.freedesktop.login1.reboot-multiple-sessions"],
        SHUTDOWN => &["org.freedesktop.login1.power-off", "org.freedesktop.login1.power-off-multiple-sessions"],
        _ => &[],
    }
}

/// The polkit actions that the presets in on need.
pub fn rights(on: &[String]) -> Vec<&'static str> {
    PRESETS.iter().filter(|p| on.iter().any(|o| o == *p)).flat_map(|p| rights_of(p).iter().copied()).collect()
}

/// Writes the polkit rule that lets the service do the presets in on, and
/// only those, or removes it when none needs a right, under root ("/" but
/// in tests). It returns the file it wrote; it runs as root, from cbb
/// action enable. The files are the full member's: one device runs one of
/// the two.
pub fn grant(root: &Path, on: &[String]) -> Result<PathBuf> {
    let ids = rights(on);
    let rules = root.join("etc/polkit-1/rules.d");
    let pkla = root.join("etc/polkit-1/localauthority/50-local.d");
    if !root.join("etc/polkit-1").exists() && !root.join("usr/share/polkit-1").exists() {
        if ids.is_empty() {
            return Ok(PathBuf::new());
        }
        return Err(Error::msg(
            "polkit is not installed here, so logind lets no service reboot this device; install polkit (polkitd, or policykit-1 on older systems) and turn the action on again",
        ));
    }
    // The old polkit has the local authority and no rules directory.
    let js = rules.exists() || !pkla.parent().is_some_and(Path::exists);
    let (path, data) =
        if js { (rules.join("60-cbb.rules"), js_rule(&ids)) } else { (pkla.join("cbb.pkla"), pkla_rule(&ids)) };
    if ids.is_empty() {
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(Error::with(format!("cannot remove {}", path.display()), e));
            }
            _ => return Ok(path),
        }
    }
    let dir = path.parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|e| Error::with(format!("cannot create {}", dir.display()), e))?;
    files::write_atomic(&path, data.as_bytes(), 0o644)?;
    Ok(path)
}

fn js_rule(ids: &[&str]) -> String {
    let q: Vec<String> = ids.iter().map(|id| format!("\"{id}\"")).collect();
    format!(
        "// Written by cbb action enable: lets the CBB service ask logind
// for the quick actions this computer's user turned on, and nothing else.
polkit.addRule(function (action, subject) {{
\tif (subject.user != \"{SERVICE_USER}\") return polkit.Result.NOT_HANDLED;
\tvar allowed = [{}];
\treturn allowed.indexOf(action.id) >= 0 ? polkit.Result.YES : polkit.Result.NOT_HANDLED;
}});
",
        q.join(", ")
    )
}

fn pkla_rule(ids: &[&str]) -> String {
    format!(
        "# Written by cbb action enable: lets the CBB service ask logind
# for the quick actions this computer's user turned on, and nothing else.
[CBB quick actions]
Identity=unix-user:{SERVICE_USER}
Action={}
ResultAny=yes
ResultInactive=yes
ResultActive=yes
",
        ids.join(";")
    )
}

/// One action in the log: who asked, when, and how it ended.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub time_ms: i64,
    /// The sender's device ID.
    pub by: String,
    /// The sender's name, when known.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The records do not show that the device `by` names signed; `by` is
    /// then only the signer's word.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unverified: bool,
    pub action: String,
    /// done, refused or failed.
    pub result: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Adds an entry to the log in dir, keeping the last LOG_SIZE.
pub fn append(dir: &Path, e: Entry) -> Result<()> {
    let mut es = read_log(dir).unwrap_or_default();
    es.push(e);
    if es.len() > LOG_SIZE {
        es.drain(..es.len() - LOG_SIZE);
    }
    let b = serde_json::to_vec(&es).context("cannot encode the action log")?;
    files::write_atomic(&dir.join(LOG_FILE), &b, 0o600)
}

/// The log in dir, oldest first.
pub fn read_log(dir: &Path) -> Result<Vec<Entry>> {
    match std::fs::read(dir.join(LOG_FILE)) {
        Ok(b) => serde_json::from_slice(&b).context(LOG_FILE),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(Error::with(format!("cannot read {}", dir.join(LOG_FILE).display()), e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cbb-actions-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn checks_the_signer_as_the_full_member() {
        let on = |name: &str| Action { name: name.into(), on: true, ..Default::default() };
        let phone = Signer { role: "phone".into(), store: "hardware".into(), ..Default::default() };
        let file_pc = Signer { role: "member".into(), store: "file".into(), ..Default::default() };
        let root = Signer { root: true, role: "phone".into(), store: "hardware".into() };
        assert!(check(&Action { name: REBOOT.into(), ..Default::default() }, &phone).unwrap().contains("is off"));
        assert_eq!(check(&on(REBOOT), &phone), None);
        assert!(check(&on(REBOOT), &file_pc).unwrap().contains("keys are in hardware"));
        assert_eq!(check(&Action { any_key: true, ..on(REBOOT) }, &file_pc), None);
        assert_eq!(check(&on(RESTART), &file_pc), None, "restart takes keys in files");
        let by_root = Action { by: vec!["root".into()], ..on(RESTART) };
        assert!(check(&by_root, &phone).unwrap().contains("only for root"));
        assert_eq!(check(&by_root, &root), None);
        assert!(check(&on(SHUTDOWN), &file_pc).unwrap().contains("keys are in hardware"));
        assert_eq!(check(&on(LOCK), &file_pc), None);
        assert_eq!(check_own("backup", &["/usr/local/bin/backup".into()]), None);
        assert!(check_own(LOCK, &["/bin/true".into()]).unwrap().contains("is a preset"));
        assert!(check_own("backup", &["backup.sh".into()]).unwrap().contains("full path"));
        assert!(check_own("Backup", &["/bin/true".into()]).unwrap().contains("not an action's name"));
        assert!(check_own("backup", &[]).unwrap().contains("needs a command"));
        assert_eq!(parse_kinds(" phone,root,phone").unwrap(), ["phone", "root"]);
        assert!(parse_kinds("admin").is_err());
    }

    #[test]
    fn keeps_settings_and_log() {
        let dir = temp("settings");
        let mut s = load(&dir).unwrap();
        assert_eq!(s, Settings::default());
        s.set(Action { name: RESTART.into(), on: true, ..Default::default() });
        s.set(Action { name: REBOOT.into(), on: true, by: vec!["phone".into()], ..Default::default() });
        save(&dir, &s).unwrap();
        let s = load(&dir).unwrap();
        assert_eq!(s.on(), [REBOOT, RESTART], "the presets keep their order");
        assert!(!s.get(CANCEL).on);
        let mut off = s.clone();
        off.all_off();
        assert!(off.on().is_empty() && off.get(REBOOT).by == ["phone"]);
        // The user's own actions come after the presets, and saving keeps
        // them as they were.
        std::fs::write(
            dir.join(SETTINGS_FILE),
            r#"{"actions":[{"name":"reboot","on":true,"any_key":true},{"name":"backup","on":true,"command":["/bin/true"]}]}"#,
        )
        .unwrap();
        let mut s = load(&dir).unwrap();
        assert!(s.get(REBOOT).any_key);
        assert_eq!(s.on(), [REBOOT, "backup"]);
        assert!(s.has("backup") && s.has(LOCK) && !s.has("backups"));
        assert_eq!(s.all().last().unwrap().name, "backup");
        s.set(Action { name: RESTART.into(), on: true, ..Default::default() });
        save(&dir, &s).unwrap();
        let mut s = load(&dir).unwrap();
        assert_eq!(s.get("backup").command, ["/bin/true"]);
        assert!(s.get("backup").on);
        assert!(!s.remove(REBOOT), "a preset stays");
        assert!(s.remove("backup") && !s.has("backup"));
        for i in 0..LOG_SIZE + 3 {
            let e = Entry { time_ms: i as i64, action: REBOOT.into(), result: "done".into(), ..Default::default() };
            append(&dir, e).unwrap();
        }
        let es = read_log(&dir).unwrap();
        assert_eq!((es.len(), es[0].time_ms), (LOG_SIZE, 3));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn grants_only_the_rights_that_are_on() {
        let dir = temp("polkit");
        assert!(grant(&dir, &[REBOOT.into()]).is_err(), "no polkit");
        assert_eq!(grant(&dir, &[RESTART.into()]).unwrap(), PathBuf::new(), "restart needs no right");
        std::fs::create_dir_all(dir.join("etc/polkit-1/rules.d")).unwrap();
        let path = grant(&dir, &[REBOOT.into(), RESTART.into()]).unwrap();
        let rule = std::fs::read_to_string(&path).unwrap();
        assert!(path.ends_with("60-cbb.rules"));
        assert!(rule.contains(
            r#"var allowed = ["org.freedesktop.login1.reboot", "org.freedesktop.login1.reboot-multiple-sessions"];"#
        ));
        assert!(rule.contains(r#"subject.user != "cbb""#));
        grant(&dir, &[RESTART.into()]).unwrap();
        assert!(!path.exists(), "the rule goes with the last right");
        let old = temp("pkla");
        std::fs::create_dir_all(old.join("etc/polkit-1/localauthority")).unwrap();
        let path = grant(&old, &[REBOOT.into()]).unwrap();
        assert!(path.ends_with("cbb.pkla"));
        assert!(std::fs::read_to_string(&path).unwrap().contains(
            "Identity=unix-user:cbb\nAction=org.freedesktop.login1.reboot;org.freedesktop.login1.reboot-multiple-sessions\n"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&old).unwrap();
    }

    #[test]
    fn reads_polkit_no() {
        assert!(denied("Failed to schedule shutdown: Access denied"));
        assert!(denied("Call to ScheduleShutdown failed: Interactive authentication required."));
        assert!(!denied("Failed to connect to bus: No such file or directory"));
    }
}
