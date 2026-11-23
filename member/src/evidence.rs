// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Attestations of member keys (docs/protocol.md, section 17, "Evidence",
//! "TPM evidence" and "Revoked attestations"). The group's root checks the
//! evidence its peers send and records what it proves in their device
//! records; a computer whose member key is in a TPM sends its own and opens
//! the root's credential. The checks of Android's Key Attestation and of
//! the TPM's structures, the TPM itself and the fetching of the revocation
//! list are cbb-helper's (internal/helper/attest.go); without a helper a
//! member neither checks nor sends evidence.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cbb_core::certs::b64;
use cbb_core::release::{self, File, Seen};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::control::Header;
use crate::error::{Context, Error, Result};
use crate::files::write_atomic;

/// How long the helper may take for an attestation: a TPM is slow.
const HELPER_TIME: Duration = Duration::from_secs(60);

/// The file in the state directory that keeps the last revocation list
/// taken, as Go's statusFile.
pub const STATUS_FILE: &str = "attest-status.json";

/// What an attestation shows of a key: its store and kind, why it is not
/// proven.
#[derive(Deserialize, Default, Debug, Clone)]
pub struct Proven {
    #[serde(default)]
    pub store: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub why: String,
}

/// The credential the root sent a device, and what it expects back.
#[derive(Deserialize)]
pub(crate) struct Challenge {
    pub evidence: Value,
    #[serde(with = "b64")]
    pub value: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Kept {
    keys: File,
    status: File,
    seen: Seen,
}

/// The revocations of a kept list under roots at now_ms, and why it is not
/// current when it is not: a list that checked out when it was signed
/// still counts once it has run out, since no list would revoke nothing.
fn kept_revocations(k: &Kept, roots: &[release::Key], now_ms: i64) -> Option<(Vec<String>, Option<String>)> {
    match release::check_status(&k.keys, &k.status, roots, now_ms, &Seen::default()) {
        Ok((st, _)) => Some((st.android_revoked, None)),
        Err(e) => {
            let at = serde_json::from_slice::<Value>(&k.status.body)
                .ok()
                .and_then(|v| v.get("time_ms").and_then(Value::as_i64))
                .filter(|&t| t > 0 && t <= now_ms)?;
            let (st, _) = release::check_status(&k.keys, &k.status, roots, at, &Seen::default()).ok()?;
            Some((st.android_revoked, Some(e.message().to_string())))
        }
    }
}

/// The attestation roots a test names in CBB_TEST_ATTEST_ROOTS (a PEM file
/// of public keys), in place of Google's, as cbb-helper reads them.
#[cfg(feature = "tunnel")]
pub(crate) fn test_attest_roots() -> Option<Vec<Vec<u8>>> {
    let f = crate::testbuild::env_os("CBB_TEST_ATTEST_ROOTS")?;
    crate::update::read_public_keys(Path::new(&f)).ok()
}

/// Checks an Android evidence (the helper's JSON form) of the key spki for
/// the group tag under the revoked serial numbers, with the core's checks
/// (cbb_core::attest) and as cbb-helper's attest-android does: on a phone
/// that is the group's root, which has no helper. A chain a revoked
/// certificate made shows hardware, unproven.
#[cfg(feature = "tunnel")]
pub fn check_android_here(e: &Value, spki: &[u8], tag: &str, revoked: &[String]) -> Result<Proven> {
    use cbb_core::attest::{self, Policy};
    #[derive(Deserialize)]
    struct Android {
        #[serde(default)]
        group_tag: String,
        #[serde(with = "b64", default)]
        salt: Vec<u8>,
        #[serde(with = "b64::list", default)]
        chain: Vec<Vec<u8>>,
    }
    let e: Android =
        serde_json::from_value(e.clone()).map_err(|_| Error::msg("an attestation that is not understood"))?;
    if !e.group_tag.is_empty() && e.group_tag != tag {
        return Err(Error::msg("invalid attestation: an attestation made for another group"));
    }
    let challenge = attest::challenge(&e.group_tag, &[], &e.salt).map_err(|i| Error::msg(i.to_string()))?;
    let roots = test_attest_roots();
    let policy = Policy { strict: false, revoked, roots: roots.as_deref() };
    match attest::check(&e.chain, spki, &challenge, &policy) {
        Ok(s) => Ok(Proven { store: s.store, kind: s.kind, why: s.why }),
        // The keys may still be in hardware, as the hello says, but Google
        // no longer vouches for the chain.
        Err(i) if i.revoked => {
            Ok(Proven { store: attest::STORE_HARDWARE.to_string(), why: i.to_string(), ..Proven::default() })
        }
        Err(i) => Err(Error::msg(i.to_string())),
    }
}

/// The attestations a member checks and sends.
pub struct Attestations {
    dir: PathBuf,
    /// The serial numbers the revocation list taken last revokes.
    revoked: Mutex<Vec<String>>,
}

/// Bytes as a JSON string in base64, as Go's []byte.
pub(crate) fn b64_value(b: &[u8]) -> Value {
    #[derive(Serialize)]
    struct W<'a>(#[serde(with = "b64")] &'a [u8]);
    serde_json::to_value(W(b)).unwrap_or_default()
}

pub(crate) fn call(op: &str, req: &impl Serialize) -> Result<Vec<u8>> {
    call_by(crate::helper::shared(), op, req)
}

/// [`call`] through the helper given, none when there is no helper.
fn call_by(helper: Option<Arc<crate::helper::Helper>>, op: &str, req: &impl Serialize) -> Result<Vec<u8>> {
    let helper = helper.ok_or_else(|| Error::msg("attestations need cbb-helper beside cbb"))?;
    let payload = serde_json::to_vec(req).context("cannot encode an attestation request")?;
    Ok(helper.call(Header { op: op.into(), ..Default::default() }, payload, HELPER_TIME)?.payload)
}

impl Attestations {
    /// The attestations of the member whose state is in dir, with the list
    /// kept there.
    pub fn new(dir: &Path) -> Arc<Attestations> {
        let a = Attestations { dir: dir.to_path_buf(), revoked: Mutex::new(Vec::new()) };
        a.load_status();
        Arc::new(a)
    }

    /// Takes the list kept in the state directory, when it still checks
    /// out: it is checked again from scratch, as the one seen last. A list
    /// that has run out still counts, as at its signing, until a newer one
    /// comes: a restart while the mirror cannot be reached drops no
    /// revocation.
    fn load_status(&self) {
        self.load_status_under(&crate::update::release_roots(), crate::update::now_ms());
    }

    /// [`Attestations::load_status`] under roots at now_ms.
    fn load_status_under(&self, roots: &[release::Key], now_ms: i64) {
        let Ok(data) = std::fs::read(self.dir.join(STATUS_FILE)) else { return };
        let Ok(k) = serde_json::from_slice::<Kept>(&data) else { return };
        if let Some((revoked, stale)) = kept_revocations(&k, roots, now_ms) {
            if let Some(why) = stale {
                eprintln!(
                    "cbb: the kept revocation list of Android attestations is not current ({why}); it counts until a newer one comes"
                );
            }
            *self.revoked.lock().unwrap() = revoked;
        }
    }

    /// The serial numbers the revocation list taken last revokes.
    pub fn revoked(&self) -> Vec<String> {
        self.revoked.lock().unwrap().clone()
    }

    /// Fetches the mirror's list and takes it when it checks out and is
    /// not older than the kept one; whether it changed, for the caller to
    /// check the peers' evidence again.
    pub fn fetch_status_with(&self, log: &dyn Fn(&str)) -> Result<bool> {
        self.fetch_status_by(crate::helper::shared(), log)
    }

    /// [`Attestations::fetch_status_with`] through the helper given.
    fn fetch_status_by(&self, helper: Option<Arc<crate::helper::Helper>>, log: &dyn Fn(&str)) -> Result<bool> {
        #[derive(Deserialize)]
        struct Files {
            keys: File,
            status: File,
        }
        let f: Files = serde_json::from_slice(&call_by(helper, "attest-status", &serde_json::json!({}))?)
            .context("the revocation list's files do not decode")?;
        Ok(self.take_status(f.keys, f.status, log)?.1)
    }

    /// Takes the list's files (keys.json and attest-status.json, fetched
    /// by the helper or, on a phone, by its app) when they check out under
    /// the release roots and are not older than the kept list: how many
    /// certificates the list revokes, and whether it changed.
    pub fn take_status(&self, keys: File, status: File, log: &dyn Fn(&str)) -> Result<(usize, bool)> {
        self.take_status_under(keys, status, &crate::update::release_roots(), crate::update::now_ms(), log)
    }

    /// [`Attestations::take_status`] under roots at now_ms.
    fn take_status_under(
        &self,
        keys: File,
        status: File,
        roots: &[release::Key],
        now_ms: i64,
        log: &dyn Fn(&str),
    ) -> Result<(usize, bool)> {
        let path = self.dir.join(STATUS_FILE);
        let kept_seen = std::fs::read(&path)
            .ok()
            .and_then(|d| serde_json::from_slice::<Kept>(&d).ok())
            .map(|k| k.seen)
            .unwrap_or_default();
        let (st, seen) = release::check_status(&keys, &status, roots, now_ms, &kept_seen)?;
        let n = st.android_revoked.len();
        // The same list is the same seq under the same keys; the rest of
        // Seen (channel_keys_seq) may be filled in on a later check.
        if (seen.status_seq, seen.status_keys_seq) == (kept_seen.status_seq, kept_seen.status_keys_seq) {
            return Ok((n, false));
        }
        let data = serde_json::to_vec(&Kept { keys, status, seen }).context("cannot encode the list")?;
        write_atomic(&path, &data, 0o600)?;
        *self.revoked.lock().unwrap() = st.android_revoked;
        log(&format!(
            "cbb: took the revocation list of Android attestations of {}, {n} certificates",
            crate::global_cli::utc_date(st.time_ms)
        ));
        Ok((n, true))
    }
}

#[cfg(test)]
mod tests {

    use super::{Attestations, Kept, STATUS_FILE, kept_revocations};
    use cbb_core::release::testing::TestKey;
    use cbb_core::release::{File, Seen};
    #[cfg(unix)]
    use std::sync::Arc;
    use std::sync::Mutex;

    const AT: i64 = 1_800_000_000_000;
    const DAY: i64 = 86_400_000;

    /// The keys file root signs for status, and a list status signs of seq
    /// at time_ms revoking revoked.
    fn list(root: &TestKey, status: &TestKey, seq: u64, time_ms: i64, revoked: &[&str]) -> (File, File) {
        let sign = |k: &TestKey, v: serde_json::Value| k.sign(&serde_json::to_vec(&v).unwrap());
        let keys = sign(
            root,
            serde_json::json!({"v": 1, "type": "keys", "seq": 1, "time_ms": AT, "expires_ms": AT + 90 * DAY,
                "keys": status.keys("status", "status")}),
        );
        let list = sign(
            status,
            serde_json::json!({"v": 1, "type": "attest-status", "seq": seq, "time_ms": time_ms,
                "expires_ms": time_ms + 7 * DAY, "android_revoked": revoked}),
        );
        (keys, list)
    }

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cbb-evidence-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A list that checks out is taken and kept, the same one again changes
    /// nothing, a newer one replaces it, one under other roots is refused,
    /// and a member started again takes the kept list, even once it ran out.
    #[test]
    fn a_list_is_taken_kept_and_taken_again() {
        let dir = tempdir("take");
        let (root, status) = (TestKey::new(1), TestKey::new(2));
        let roots = root.root("root-1");
        let a = Attestations::new(&dir);
        assert!(a.revoked().is_empty());
        let said = Mutex::new(Vec::new());
        let log = |l: &str| said.lock().unwrap().push(l.to_string());

        let (keys, first) = list(&root, &status, 1, AT, &["1f", "2a"]);
        assert_eq!(a.take_status_under(keys.clone(), first.clone(), &roots, AT + DAY, &log).unwrap(), (2, true));
        assert_eq!(a.revoked(), ["1f", "2a"]);
        assert!(said.lock().unwrap()[0].contains("2 certificates"));
        assert!(dir.join(STATUS_FILE).exists());
        assert_eq!(a.take_status_under(keys.clone(), first, &roots, AT + DAY, &log).unwrap(), (2, false));
        assert_eq!(said.lock().unwrap().len(), 1);

        let (_, newer) = list(&root, &status, 2, AT + DAY, &["3c"]);
        assert_eq!(a.take_status_under(keys.clone(), newer.clone(), &roots, AT + 2 * DAY, &log).unwrap(), (1, true));
        assert_eq!(a.revoked(), ["3c"]);
        assert!(a.take_status_under(keys, newer, &status.root("root-2"), AT + 2 * DAY, &log).is_err());
        assert_eq!(a.revoked(), ["3c"]);

        let again = Attestations { dir: dir.clone(), revoked: Mutex::new(Vec::new()) };
        again.load_status_under(&roots, AT + 2 * DAY);
        assert_eq!(again.revoked(), ["3c"]);
        let stale = Attestations { dir: dir.clone(), revoked: Mutex::new(Vec::new()) };
        stale.load_status_under(&roots, AT + 60 * DAY);
        assert_eq!(stale.revoked(), ["3c"]);
        let other = Attestations { dir: dir.clone(), revoked: Mutex::new(Vec::new()) };
        other.load_status_under(&status.root("root-2"), AT + 2 * DAY);
        assert!(other.revoked().is_empty());

        // A kept file that does not decode is no list.
        std::fs::write(dir.join(STATUS_FILE), b"not json").unwrap();
        let broken = Attestations { dir: dir.clone(), revoked: Mutex::new(Vec::new()) };
        broken.load_status_under(&roots, AT + 2 * DAY);
        assert!(broken.revoked().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fetching the list needs the helper, and its answer must decode.
    #[test]
    fn fetching_the_list_needs_the_helper() {
        let dir = tempdir("fetch");
        let a = Attestations::new(&dir);
        let none = a.fetch_status_by(None, &|_| {}).err().unwrap();
        assert!(none.message().contains("need cbb-helper"), "{}", none.message());
        // The fake helper runs this test program, which only Unix can.
        #[cfg(unix)]
        {
            let helper = Arc::new(crate::helper::tests::fake(Arc::new(Mutex::new(Vec::new()))));
            let bad = a.fetch_status_by(Some(helper), &|_| {}).err().unwrap();
            assert!(bad.message().contains("do not decode"), "{}", bad.message());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An Android evidence that is not understood, made for another group
    /// or with no chain is refused.
    #[cfg(feature = "tunnel")]
    #[test]
    fn android_evidence_is_refused() {
        use super::check_android_here;
        let refused = |e: serde_json::Value| check_android_here(&e, &[1, 2, 3], "tag", &[]).err().unwrap();
        assert!(refused(serde_json::json!("text")).message().contains("not understood"));
        assert!(refused(serde_json::json!({"group_tag": "other"})).message().contains("another group"));
        let empty = refused(serde_json::json!({"group_tag": "tag", "salt": "AAAA", "chain": []}));
        assert!(!empty.message().is_empty());
        assert_eq!(super::b64_value(&[1, 2, 3]), serde_json::json!("AQID"));
    }

    /// A kept list counts after it ran out, as at its signing, so a restart
    /// without the mirror drops no revocation; one that never checked out
    /// counts not at all.
    #[test]
    fn an_old_list_still_revokes() {
        let (root, status) = (TestKey::new(1), TestKey::new(2));
        let sign = |k: &TestKey, v: serde_json::Value| k.sign(&serde_json::to_vec(&v).unwrap());
        let at: i64 = 1_800_000_000_000;
        let day = 86_400_000;
        let keys = sign(
            &root,
            serde_json::json!({"v": 1, "type": "keys", "seq": 1, "time_ms": at, "expires_ms": at + 90 * day,
                "keys": status.keys("status", "status")}),
        );
        let list = sign(
            &status,
            serde_json::json!({"v": 1, "type": "attest-status", "seq": 1, "time_ms": at, "expires_ms": at + 7 * day,
                "android_revoked": ["1f", "2a"]}),
        );
        let k = Kept { keys, status: list, seen: Seen::default() };
        let roots = root.root("root-1");
        let (now, stale) = kept_revocations(&k, &roots, at + day).unwrap();
        assert_eq!(now, ["1f", "2a"]);
        assert!(stale.is_none());
        let (later, stale) = kept_revocations(&k, &roots, at + 30 * day).unwrap();
        assert_eq!(later, ["1f", "2a"]);
        assert!(stale.is_some());
        // Not under other roots.
        assert!(kept_revocations(&k, &status.root("root-2"), at + day).is_none());
    }
}
