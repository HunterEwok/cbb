// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What cbb update does differently on each system: the release's archive for this
//! device, the updater's folders, the programs an update replaces, the
//! archive's installer, unpacking, the Windows programs' signer, and the
//! daily timer on macOS (launchd), FreeBSD (cron) and Windows (a scheduled
//! task); Linux's and OpenWrt's are in update.rs.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Context, Error, Result};
use crate::files::write_atomic;

/// The program this update replaces: the one that started a copy of
/// itself to update from (CBB_UPDATE_FROM, on Windows), or this one.
pub fn installed_program() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("CBB_UPDATE_FROM").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    let exe = std::env::current_exe().context("cannot find this program")?;
    Ok(crate::files::real_path(&exe))
}

/// The architecture as the release's archives name it: what build.sh
/// built for (CBB_ARCH), or else Rust's name for it, ARM as ARMv6, which
/// runs on ARMv7 too.
fn arch() -> Option<&'static str> {
    if let Some(a) = option_env!("CBB_ARCH").filter(|a| !a.is_empty()) {
        return Some(a);
    }
    Some(match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "armv6",
        "mips" if cfg!(target_endian = "little") => "mipsle",
        "mips" => "mips",
        _ => return None,
    })
}

/// The release's archive for this device, as packaging/archive.sh names
/// them: one for each system and architecture, which carries cbb, and its
/// helper where the release builds one; None for a system the release does
/// not build for.
pub fn archive_name() -> Option<String> {
    let arch = arch()?;
    Some(match std::env::consts::OS {
        "macos" => format!("cbb-darwin-{arch}.tar.gz"),
        "windows" => format!("cbb-windows-{arch}.zip"),
        os @ ("linux" | "freebsd") => format!("cbb-{os}-{arch}.tar.gz"),
        _ => return None,
    })
}

/// The installed programs an update replaces and puts back, the main one
/// first: cbb, on Windows cbbw.exe beside it, and the Go programs beside
/// it when there are, so that a release goes back whole.
pub fn programs(main: &Path) -> Vec<PathBuf> {
    let exe = std::env::consts::EXE_SUFFIX;
    let mut names = vec![];
    if cfg!(windows) {
        names.push(format!("cbbw{exe}"));
    }
    for p in [crate::helper::PROGRAM, "cbb-forward", "cbb-relay"] {
        names.push(format!("{p}{exe}"));
    }
    let mut out = vec![main.to_path_buf()];
    out.extend(names.into_iter().map(|n| main.with_file_name(n)).filter(|p| p.is_file()));
    out
}

/// The updater's folder, which only root or SYSTEM may change, and where
/// it downloads; neither is under the service's own folders.
pub fn paths() -> (PathBuf, PathBuf) {
    let dir = if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/cbb-update")
    } else if cfg!(target_os = "freebsd") {
        PathBuf::from("/var/db/cbb-update")
    } else if cfg!(windows) {
        // Not under Program Files\cbb: install.ps1 stops every program
        // there, and cbb update runs from this folder.
        let pf = std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into());
        Path::new(&pf).join("cbb-update")
    } else if crate::rootless::is() {
        let d = crate::rootless::update_dir();
        return (d.clone(), d);
    } else if crate::openwrt() {
        // /etc survives a sysupgrade; the downloads go to RAM.
        return (PathBuf::from("/etc/cbb-update"), PathBuf::from("/tmp/cbb-update"));
    } else if in_opt() {
        // SteamOS and other systems whose /usr is read-only: the program is
        // in /opt/cbb, and its updater beside it (/var is small on SteamOS;
        // /opt lives in /home).
        return (PathBuf::from("/opt/cbb-update"), PathBuf::from("/opt/cbb-update"));
    } else {
        PathBuf::from("/var/lib/cbb-update")
    };
    (dir.clone(), dir)
}

/// Whether this program is the one installed in /opt/cbb, as on SteamOS.
fn in_opt() -> bool {
    cfg!(target_os = "linux")
        && std::env::current_exe().and_then(std::fs::canonicalize).is_ok_and(|p| p == Path::new("/opt/cbb/bin/cbb"))
}

/// The installer of this system in an unpacked archive's top folder.
fn install_script(root: &Path) -> PathBuf {
    let rel = if cfg!(windows) {
        "packaging/windows/install.ps1"
    } else if cfg!(target_os = "macos") {
        "packaging/macos/install.sh"
    } else if cfg!(target_os = "freebsd") {
        "packaging/freebsd/install.sh"
    } else if crate::openwrt() {
        "packaging/openwrt/install.sh"
    } else {
        "packaging/linux/install.sh"
    };
    root.join(rel)
}

/// Runs the installer of an unpacked archive on bin, as an update: it asks
/// nothing (CBB_UPDATING) and keeps the port and the other settings.
pub fn install(root: &Path, bin: &Path) -> Result<()> {
    let script = install_script(root);
    let name = script.file_name().and_then(|n| n.to_str()).unwrap_or("install.sh").to_string();
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("powershell.exe");
        c.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]).arg(&script).arg("-Bin").arg(bin);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg(&script);
        if crate::rootless::is() {
            c.arg("--rootless");
        }
        c.arg(bin);
        c
    };
    let out = cmd.env("CBB_UPDATING", "1").output().context(format!("cannot run {name}"))?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    Err(Error::msg(format!("{name} failed: {}", failure(&text, &name))))
}

/// The installer's own line about what failed ("install.sh: ..."), or
/// else its last lines.
pub fn failure(out: &str, script: &str) -> String {
    let lines: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let prefix = format!("{script}: ");
    if let Some(l) = lines.iter().rev().find(|l| l.starts_with(&prefix)) {
        return l[prefix.len()..].to_string();
    }
    lines[lines.len().saturating_sub(3)..].join(" / ")
}

/// Unpacks the archive file into the folder out: tar, which on Windows
/// (bsdtar) opens a zip file too.
pub fn unpack(file: &Path, out: &Path) -> Result<std::process::Output> {
    // -o: the files are this user's (root's), never those of the uid that
    // packed them, which may be a user of this device.
    let flags = if cfg!(windows) { "-xf" } else { "-xzof" };
    Command::new("tar").arg(flags).arg(file).arg("-C").arg(out).output().context("cannot run tar")
}

/// On Windows, refuses new programs that are not Authenticode-signed by
/// the signer of the installed ones, when those are signed, as Go's
/// VerifySigner: any valid signature is not enough. Unsigned installed
/// programs leave release.json as the only check. Elsewhere it checks
/// nothing more.
pub fn verify_signer(installed: &[PathBuf], unpacked: &[PathBuf]) -> Result<()> {
    if !cfg!(windows) {
        return Ok(());
    }
    for (old, new) in installed.iter().zip(unpacked) {
        let (status, subject) = authenticode(old)?;
        if status != "Valid" {
            continue;
        }
        let (s, subj) = authenticode(new)?;
        if s != "Valid" || subj != subject {
            return Err(Error::msg(format!(
                "the new {} is not signed by {subject} (its signature: {s} {subj}); not installing it",
                new.display()
            )));
        }
    }
    Ok(())
}

/// What Get-AuthenticodeSignature says of a file: its status and its
/// signer's subject.
fn authenticode(path: &Path) -> Result<(String, String)> {
    let p = path.display().to_string().replace('\'', "''");
    let script = format!(
        "$s = Get-AuthenticodeSignature -LiteralPath '{p}'\n\
         $subject = if ($s.SignerCertificate) {{ $s.SignerCertificate.Subject }} else {{ '' }}\n\
         [pscustomobject]@{{ status = [string]$s.Status; subject = $subject }} | ConvertTo-Json -Compress"
    );
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .context(format!("checking the signature of {}", path.display()))?;
    #[derive(serde::Deserialize)]
    struct Sig {
        status: String,
        #[serde(default)]
        subject: String,
    }
    let s: Sig =
        serde_json::from_slice(&out.stdout).context(format!("checking the signature of {}", path.display()))?;
    Ok((s.status, s.subject))
}

const LAUNCHD_LABEL: &str = "tools.cbb.update";
const CRON_FREEBSD: &str = "/usr/local/etc/cron.d/cbb-update";
const WINDOWS_TASK: &str = "cbb update";

/// A time of day of this device's own for a timer without a random delay:
/// between 1:00 and 6:59.
fn at() -> (u8, u8) {
    let r = cbb_core::certs::random_bytes::<2>();
    (1 + r[0] % 6, r[1] % 60)
}

/// The daily timer that runs exe update -timer on macOS, FreeBSD and
/// Windows; None on the systems update.rs times itself.
pub fn set_timer(on: bool, exe: &Path) -> Option<Result<()>> {
    if cfg!(target_os = "macos") {
        Some(launchd_timer(on, exe))
    } else if cfg!(target_os = "freebsd") {
        Some(freebsd_timer(on, exe))
    } else if cfg!(windows) {
        Some(windows_timer(on, exe))
    } else {
        None
    }
}

fn run(name: &str, args: &[&str]) -> Result<()> {
    let o = Command::new(name).args(args).output().context(format!("cannot run {name}"))?;
    if o.status.success() {
        return Ok(());
    }
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    Err(Error::msg(format!("{name} {}: {}", args.join(" "), text.trim())))
}

fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(Error::with(format!("cannot remove {}", path.display()), e)),
        _ => Ok(()),
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn launchd_timer(on: bool, exe: &Path) -> Result<()> {
    let plist = PathBuf::from(format!("/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"));
    let _ = Command::new("launchctl").args(["bootout", &format!("system/{LAUNCHD_LABEL}")]).output();
    if !on {
        return remove(&plist);
    }
    let (h, m) = at();
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by cbb update -auto on; cbb update -auto off removes it. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LAUNCHD_LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{}</string>
		<string>update</string>
		<string>-timer</string>
	</array>
	<key>StartCalendarInterval</key>
	<dict>
		<key>Hour</key>
		<integer>{h}</integer>
		<key>Minute</key>
		<integer>{m}</integer>
	</dict>
</dict>
</plist>
"#,
        xml_escape(&exe.display().to_string())
    );
    write_atomic(&plist, body.as_bytes(), 0o644)?;
    run("launchctl", &["bootstrap", "system", &plist.display().to_string()])
}

fn freebsd_timer(on: bool, exe: &Path) -> Result<()> {
    let file = Path::new(CRON_FREEBSD);
    if !on {
        return remove(file);
    }
    let (h, m) = at();
    let line = format!(
        "# Written by cbb update -auto on; cbb update -auto off removes it.\n{m} {h} * * * root {} update -timer\n",
        exe.display()
    );
    fs::create_dir_all("/usr/local/etc/cron.d").context("cannot make /usr/local/etc/cron.d")?;
    write_atomic(file, line.as_bytes(), 0o644)
}

fn windows_timer(on: bool, exe: &Path) -> Result<()> {
    // Unregister-ScheduledTask fails without the task, whatever its
    // ErrorAction says.
    let mut script = format!(
        "if (Get-ScheduledTask -TaskName '{WINDOWS_TASK}' -ErrorAction SilentlyContinue) {{ Unregister-ScheduledTask -TaskName '{WINDOWS_TASK}' -Confirm:$false }}"
    );
    if on {
        // The windowless cbbw.exe beside cbb.exe: no console flashes up.
        let w = exe.with_file_name("cbbw.exe").display().to_string().replace('\'', "''");
        script = format!(
            "$ErrorActionPreference = 'Stop'\n\
             $a = New-ScheduledTaskAction -Execute '{w}' -Argument 'update -timer'\n\
             $t = New-ScheduledTaskTrigger -Daily -At 1am -RandomDelay (New-TimeSpan -Hours 6)\n\
             $p = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest\n\
             $s = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)\n\
             Register-ScheduledTask -TaskName '{WINDOWS_TASK}' -Description 'Checks for a CBB update once a day (cbb update -auto off removes it).' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null"
        );
    }
    run("powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", &script])
}

/// Runs cbb update again from a copy of this program in the updater's
/// folder dir, as install.ps1 stops every program in Program Files\cbb,
/// and exits with its code: Go's updateFromCopy.
pub fn update_from_copy(dir: &Path, exe: &Path, args: &[String]) -> Result<()> {
    let run_dir = dir.join("run");
    fs::create_dir_all(&run_dir).context(format!("cannot make {}", run_dir.display()))?;
    let copy = run_dir.join(format!("cbb-update{}", std::env::consts::EXE_SUFFIX));
    fs::copy(exe, &copy).context(format!("copying cbb to {}", run_dir.display()))?;
    // install.ps1 leaves this process running and renames its program
    // aside.
    let st = Command::new(&copy)
        .arg("update")
        .args(args)
        .env("CBB_UPDATE_FROM", exe)
        .env("CBB_UPDATE_PARENT", std::process::id().to_string())
        .status()
        .context(format!("cannot run {}", copy.display()))?;
    std::process::exit(st.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_takes_the_installers_line() {
        assert_eq!(
            failure("a\ninstall.ps1: copying failed: in use\nat line 3\n", "install.ps1"),
            "copying failed: in use"
        );
        assert_eq!(
            failure("a\ninstall.sh: copying failed: no space\nmore\n", "install.sh"),
            "copying failed: no space"
        );
        assert_eq!(failure("one\n\ntwo\nthree\nfour\n", "install.sh"), "two / three / four");
    }

    #[test]
    fn archive_of_the_system() {
        let name = archive_name().unwrap();
        assert!(name.starts_with("cbb-") && !name.contains("lite"), "{name}");
        let dir = std::env::temp_dir().join(format!("cbb-update-os-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cbb = dir.join(format!("cbb{}", std::env::consts::EXE_SUFFIX));
        fs::write(&cbb, b"").unwrap();
        assert_eq!(programs(&cbb).len(), 1);
        fs::write(dir.join(format!("cbb-helper{}", std::env::consts::EXE_SUFFIX)), b"").unwrap();
        assert_eq!(programs(&cbb).len(), if cfg!(windows) { 1 } else { 2 });
        fs::remove_dir_all(&dir).unwrap();
    }
}
