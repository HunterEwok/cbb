// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The project's push service (`cbb-push`, format section 20.4,
//! `cbb_core::push`): members of a group ask it to wake a phone whose app
//! is closed, and it passes a sealed body of one size to the phone's
//! platform (APNs for the iPhone and the iPad, FCM for Android with Play
//! services, UnifiedPush for Android without; Push Kit follows). It holds
//! the platforms' keys and none of a group's.
//!
//! - A member connects over TLS with ALPN `cbb-push/1` to the service's
//!   pinned key, presenting the certificate of its server key for the
//!   service's face, and sends `push/hello` with the face's hubs' and
//!   members' credentials (format section 8). The service takes the first
//!   period key it sees for a tag, never an older version of a credential,
//!   and the member only when the members' credential lists its key.
//! - Then `push/send` as often as the budgets allow: per tag, per token,
//!   per address. Every honest sender of one body makes the same bytes, so
//!   a body already sent to a token within a day is answered `repeat` and
//!   not sent again: several members sending one copy give one
//!   notification.
//! - Each send carries the phone's send key for the token, its signature
//!   over (env, token, slot, the group's face, seq, and the service's
//!   challenge when the registration has one), the slot and seq. The face
//!   is not sent: the service checks the signature over the face of the
//!   connection, so a registration holds only on its own group's. The token's binding
//!   (`binding.rs`) says whether it passes: a key is confirmed only by a
//!   challenge the service sent to the token (computed from the service's
//!   secret, never kept, so no other key can push it out), and then only
//!   that key sends; seq is kept per key and slot, one slot for each of
//!   the phone's groups. A send it refuses is answered `stale`, one whose
//!   seq is more than a day past its clock `ahead`, one of a key algorithm
//!   it does not take `key`.
//! - What a send leaves (a binding, a repeat) is written only once the
//!   platform took the body, judged again over the binding as it is then;
//!   a second send of a body still on its way is answered `failed` with a
//!   short wait, so a slow platform never makes a body a repeat that was
//!   not sent. A repeat with a later expiry than the first passes once.
//! - Every send costs its tag's budget, a refused one too, and a
//!   connection is closed after a few refusals. What goes to one token is
//!   budgeted per group and per token: under the confirmed key (a rate per
//!   group and one ceiling for every group together), while no key is
//!   confirmed (a small rate per group, and one ceiling for every group
//!   together, past which a group's send carries only its challenge,
//!   unless the group sent nothing to the token lately), and for
//!   challenges alone. The tables everyone shares (repeats, bindings,
//!   the budgets) give each payer (an address, an IPv6 /64) a share: when
//!   one is full, the payer with the most entries loses its oldest (an
//!   unconfirmed binding before a confirmed one, and of the confirmed the
//!   one used longest ago), and no one is refused for it. Connections are counted per payer too.
//! - It sees its face's tag, server keys' hashes, tokens, times and one
//!   size per platform. The tags, the budgets and the repeats stay in
//!   memory (a repeat does not outlive a restart); the bindings are kept in
//!   its state file and journal (mode 0600, `saved.rs`) with the secret of
//!   the keyed hashes they are filed under (which also makes the
//!   challenges), written before a send that changed one is answered
//!   `sent` (a send whose change could not be written is answered
//!   `failed`, and the next snapshot keeps it), and hold no token and no
//!   address. A missing
//!   state file stops the start unless it is the first. It logs counts,
//!   never a token, a tag or an address.

pub mod apns;
pub mod binding;
pub mod command;
pub mod fcm;
pub mod h2;
mod saved;
mod shares;
pub mod unifiedpush;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cbb_core::blind::credential::{Credential, TYPE_HUBS, TYPE_MEMBERS};
use cbb_core::format::cbor::Value;
use cbb_core::format::{Alg, Key, frame};
use cbb_core::push;
use hmac::{Hmac, KeyInit, Mac};
use rustls::{ServerConnection, StreamOwned};
use sha2::Sha256;

pub use binding::Binding;
use binding::{Ask, Verdict};
use shares::{Payer, Shared};

use crate::error::{Context, Error, Result};

/// What a platform did with a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Sent,
    /// The token is dead (the app was removed): the members drop it.
    Gone,
    /// Not now; try after this long.
    Later(Duration),
    /// The service has no way to this platform.
    NoPath,
}

/// A challenge for the token's holder: the value its next registration
/// signs, and the first 8 bytes of the hash of the send key it was made
/// for, so that the app keeps only one made for its own key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge {
    pub value: [u8; 16],
    pub key: [u8; 8],
}

impl Challenge {
    /// The 24 bytes the platforms carry.
    pub fn bytes(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[..16].copy_from_slice(&self.value);
        out[16..].copy_from_slice(&self.key);
        out
    }
}

/// What the service hands a platform: a body, a challenge, or both.
#[derive(Debug, Clone, Copy)]
pub struct Delivery<'a> {
    pub env: u64,
    pub token: &'a [u8],
    pub body: Option<&'a [u8]>,
    pub challenge: Option<Challenge>,
    /// When the platform drops it if the phone is not reached (Unix
    /// seconds).
    pub expires_s: u64,
    /// The keyed hash of the group's tag that asked, for the budgets a
    /// platform keeps of its own.
    pub tag: [u8; 32],
}

/// A platform's push service.
pub trait Platform: Send + Sync {
    fn send(&self, d: &Delivery<'_>) -> Outcome;
}

/// The budgets (format section 20.4, P-4): sends an hour and the burst.
/// What goes to one token is budgeted per group (its tag), so that no
/// group, a made-up one included, spends another's.
#[derive(Clone, Copy, Debug)]
pub struct Budgets {
    /// Bodies to one token from one group, under the token's confirmed
    /// key (or the send that confirms it).
    pub per_token: (f64, f64),
    /// Bodies to one token under its confirmed key from every group
    /// together.
    pub per_token_all: (f64, f64),
    pub per_tag: (f64, f64),
    /// Bodies to a token no key is confirmed for: from one group, and
    /// from every group together; past the second a group's send carries
    /// only its challenge, as a push with no body.
    pub unconfirmed: (f64, f64),
    pub unconfirmed_token: (f64, f64),
    /// Challenges with no body to one token from one group.
    pub challenges: (f64, f64),
    /// Connections at once, in all and from one payer, and of those from
    /// one payer the ones that have not said hello yet.
    pub connections: usize,
    pub per_address: usize,
    pub unready: usize,
}

impl Default for Budgets {
    fn default() -> Budgets {
        Budgets {
            per_token: (120.0, 30.0),
            per_token_all: (360.0, 60.0),
            per_tag: (1200.0, 120.0),
            unconfirmed: (12.0, 4.0),
            unconfirmed_token: (30.0, 10.0),
            challenges: (4.0, 2.0),
            connections: 1024,
            per_address: 16,
            unready: 4,
        }
    }
}

pub struct Config {
    pub listen: SocketAddr,
    /// The service's TLS certificate and its PKCS #8 key.
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    /// The platforms by env.
    pub platforms: HashMap<u64, Arc<dyn Platform>>,
    pub budgets: Budgets,
    /// The file the bindings are kept in; None keeps them in memory only.
    pub state: Option<PathBuf>,
    /// The first start: the state file is made, not expected.
    pub new_state: bool,
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
}

/// How long a body sent is remembered as a repeat, and how many at most.
const REPEAT_FOR: Duration = Duration::from_secs(24 * 3600);
const REPEATS_MAX: usize = 1 << 20;
const BINDINGS_MAX: usize = 1 << 20;
/// How often a changed snapshot is written.
const SAVE_EVERY: Duration = Duration::from_secs(5);
/// Tags and token budgets kept at most. Anyone can make a period key and
/// credentials of a tag of their own, so the table of first period keys is
/// bounded three ways: an entry lives at most until its credentials expire
/// (and never longer than `TAG_LIFE` unseen), at most `TAGS_MAX` entries
/// are held (the one unseen the longest gives way), and one payer brings at
/// most `NEW_TAGS` new tags an hour.
const TAGS_MAX: usize = 65_536;
const TAG_LIFE: Duration = Duration::from_secs(31 * 24 * 3600);
const NEW_TAGS: (f64, f64) = (16.0, 16.0);
const TOKENS_MAX: usize = 1 << 20;
/// The hello within this, and at most this long between sends.
const HELLO_WAIT: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(120);
/// Refused sends on one connection before it is closed.
const REFUSALS_MAX: u32 = 8;
/// The wait a second send of a body still on its way is told.
const IN_FLIGHT_WAIT_MS: u64 = 2000;
/// The wait a send is told when its binding could not be journaled.
const JOURNAL_WAIT_MS: u64 = 5000;
/// The largest frame a member sends.
const MAX_FRAME: usize = 16_384;

/// A token bucket.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    left: f64,
    at: Instant,
}

impl Bucket {
    fn full(burst: f64, at: Instant) -> Bucket {
        Bucket { left: burst, at }
    }

    /// Whether the bucket is full at `now`: nothing was taken from it for
    /// as long as it takes to fill.
    fn full_at(&self, (per_hour, burst): (f64, f64), now: Instant) -> bool {
        let rate = per_hour / 3600.0;
        self.left + now.saturating_duration_since(self.at).as_secs_f64() * rate >= burst
    }

    fn take(&mut self, (per_hour, burst): (f64, f64), now: Instant) -> std::result::Result<(), Duration> {
        let rate = per_hour / 3600.0;
        self.left = (self.left + now.saturating_duration_since(self.at).as_secs_f64() * rate).min(burst);
        self.at = now;
        if self.left >= 1.0 {
            self.left -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(((1.0 - self.left) / rate).max(1.0)))
        }
    }
}

/// What the service holds of one tag (one group's face toward it).
struct Period {
    key: Vec<u8>,
    hubs_version: u64,
    members_version: u64,
    budget: Bucket,
    seen: Instant,
    /// When its credentials expire: the entry goes then (a period's
    /// credentials never outlive the period).
    expires_ms: u64,
}

/// One group's budgets toward one token: for bodies under the confirmed
/// key, for bodies while no key is confirmed, and for challenges with no
/// body.
#[derive(Clone, Copy, Debug)]
struct TokenBudget {
    send: Bucket,
    unconfirmed: Bucket,
    challenge: Bucket,
}

/// What every group together may send to one token.
#[derive(Clone, Copy, Debug)]
struct Ceiling {
    unconfirmed: Bucket,
    confirmed: Bucket,
}

/// A body sent: when, how long the platform keeps it, and whether a
/// longer life already passed once.
#[derive(Clone, Copy, Debug)]
struct Repeat {
    at: Instant,
    life_s: u64,
    upgraded: bool,
}

struct State {
    periods: HashMap<[u8; 32], Period>,
    /// By (token, group).
    tokens: Shared<TokenBudget>,
    /// By token: what every group together may send, while no key is
    /// confirmed and under the confirmed key.
    ceilings: Shared<Ceiling>,
    /// By (payer, token): the quiet passes past the unconfirmed ceiling.
    quiet: Shared<Bucket>,
    repeats: Shared<Repeat>,
    bindings: Shared<Binding>,
    /// Bodies on their way to a platform.
    in_flight: HashSet<[u8; 32]>,
    /// The bindings changed since the snapshot was last written.
    dirty: bool,
    /// The number of the last change to a binding.
    ver: u64,
    journal: Option<saved::Journal>,
    connections: usize,
    per_payer: HashMap<Payer, usize>,
    unready: HashMap<Payer, usize>,
    /// New tags each payer may bring.
    new_tags: HashMap<Payer, Bucket>,
}

struct Inner {
    cfg: Config,
    tls: Arc<rustls::ServerConfig>,
    /// The secret of the keyed hashes, drawn on the first start and kept
    /// with the bindings.
    secret: [u8; 32],
    state: Mutex<State>,
    /// One save at a time: the saver's and the stop's.
    saving: Mutex<()>,
    stop: AtomicBool,
    sent: AtomicU64,
}

/// A running service.
pub struct Service {
    inner: Arc<Inner>,
    addr: SocketAddr,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// Whose share an address uses: the address, or its /64 for IPv6, an IPv4
/// client on an IPv6 socket read as the IPv4 address it is.
pub fn payer_addr(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::from(o)
        }
        v4 => v4,
    }
}

/// What a send asked the platform for, to finish once it answered.
enum Plan {
    Body {
        repeat: [u8; 32],
        upgrade: bool,
        challenge: Option<[u8; 16]>,
    },
    /// A challenge alone, and what the send is answered whatever the
    /// platform did with it; `file`, the send to file a binding by when the
    /// token has none.
    Challenge {
        value: [u8; 16],
        answer: Answer,
        file: Option<Ask>,
    },
}

/// What one send came to: the status, the wait, and whether it counts as
/// refused on its connection.
struct Answer {
    status: u64,
    retry: Option<u64>,
    refused: bool,
}

fn answer(status: u64, retry: Option<u64>) -> Answer {
    Answer { status, retry, refused: false }
}

fn refused(status: u64) -> Answer {
    Answer { status, retry: None, refused: true }
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn keyed(&self, what: &[u8], a: &[u8], b: &[u8]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.secret).expect("HMAC takes any key");
        m.update(what);
        m.update(&(a.len() as u32).to_be_bytes());
        m.update(a);
        m.update(b);
        m.finalize().into_bytes().into()
    }

    /// The token's challenge for a send key, a binding's generation and a
    /// period: computed again to check an answer, never kept.
    fn challenge(&self, tok: &[u8; 32], key: &[u8; 32], generation: u32, period: u64) -> [u8; 16] {
        let mut what = [0u8; 44];
        what[..32].copy_from_slice(key);
        what[32..36].copy_from_slice(&generation.to_be_bytes());
        what[36..].copy_from_slice(&period.to_be_bytes());
        let h = self.keyed(b"challenge", tok, &what);
        let mut out = [0u8; 16];
        out.copy_from_slice(&h[..16]);
        out
    }

    fn payer(&self, ip: IpAddr) -> Payer {
        let p = match payer_addr(ip) {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };
        let h = self.keyed(b"payer", &p, &[]);
        let mut out = [0u8; 16];
        out.copy_from_slice(&h[..16]);
        out
    }

    /// Checks a hello: the face's hubs' and members' credentials and the
    /// member's server key among the members. Returns the tag's keyed hash
    /// and the face's tag itself, which a registration's signature covers.
    fn hello(
        &self,
        creds: &[&[u8]],
        server_key: &[u8],
        now: u64,
        payer: Payer,
    ) -> std::result::Result<([u8; 32], [u8; 16]), &'static str> {
        let mut hubs = None;
        let mut members = None;
        for c in creds {
            let c = Credential::read(c).map_err(|_| "the group's credentials do not verify")?;
            match c.kind {
                TYPE_HUBS => hubs = Some(c),
                TYPE_MEMBERS => members = Some(c),
                _ => return Err("only the hubs' and members' credentials are taken"),
            }
        }
        let (Some(hubs), Some(members)) = (hubs, members) else {
            return Err("the hubs' and members' credentials are needed");
        };
        if !hubs.live(now) || !members.live(now) {
            return Err("the group's credentials expired");
        }
        let by_period = members.signer == hubs.signer;
        let by_admin = hubs.admins.contains(&members.signer_hash().0);
        if members.group != hubs.group || !(by_period || by_admin) {
            return Err("the members' credential is not of the hubs' period");
        }
        if !members.members.contains(&Key::new(Alg::Es256, server_key).hash().0) {
            return Err("the members' credential does not list this device");
        }
        let tag = self.keyed(b"tag", &hubs.group, &[]);
        let mut st = self.lock();
        let at = Instant::now();
        if !st.periods.contains_key(&tag) {
            if !st.new_tags.contains_key(&payer) && st.new_tags.len() >= TAGS_MAX {
                st.new_tags.retain(|_, b| at.saturating_duration_since(b.at) < Duration::from_secs(3600));
            }
            let b = st.new_tags.entry(payer).or_insert(Bucket::full(NEW_TAGS.1, at));
            if b.take(NEW_TAGS, at).is_err() {
                return Err("too many groups from this address; try later");
            }
            if st.periods.len() >= TAGS_MAX {
                st.periods.retain(|_, p| p.expires_ms > now && at.saturating_duration_since(p.seen) < TAG_LIFE);
            }
            if st.periods.len() >= TAGS_MAX {
                // Forget the period not seen the longest.
                if let Some(old) = st.periods.iter().min_by_key(|(_, p)| p.seen).map(|(k, _)| *k) {
                    st.periods.remove(&old);
                }
            }
        }
        let burst = self.cfg.budgets.per_tag.1;
        let p = st.periods.entry(tag).or_insert_with(|| Period {
            key: hubs.signer.clone(),
            hubs_version: 0,
            members_version: 0,
            budget: Bucket::full(burst, at),
            seen: at,
            expires_ms: 0,
        });
        if p.key != hubs.signer {
            return Err("another period key than the one first seen for this group");
        }
        if hubs.version < p.hubs_version || members.version < p.members_version {
            return Err("the group's credentials are older than ones seen before");
        }
        p.hubs_version = hubs.version;
        p.members_version = members.version;
        p.seen = at;
        p.expires_ms = hubs.expires_ms.min(members.expires_ms);
        Ok((tag, hubs.group))
    }

    /// Files a binding once the platform took what the send asked for:
    /// the send is judged again over the binding as it is now (another
    /// send may have changed it meanwhile), and a change of key,
    /// generation or slots is journaled before the send is answered. Err
    /// when the journal could not take it: the send is then answered
    /// `failed`, and the next snapshot keeps the change.
    fn commit(&self, st: &mut State, tok: [u8; 32], payer: Payer, ask: &Ask, born: u32) -> std::result::Result<(), ()> {
        let now = now_ms();
        let current = st.bindings.get(&tok).cloned();
        let mint = |k: &[u8; 32], g: u32, p: u64| self.challenge(&tok, k, g, p);
        let then = match binding::judge(current.as_ref(), ask, now, born, &mint) {
            Verdict::Pass { then, .. } => then,
            Verdict::Stale | Verdict::Ahead | Verdict::Challenge { .. } => return Ok(()),
        };
        if current.as_ref() == Some(&then) {
            return Ok(());
        }
        let meaningful = current
            .as_ref()
            .is_none_or(|c| c.key != then.key || c.generation != then.generation || c.slots != then.slots);
        let payer = st.bindings.payer(&tok).unwrap_or(payer);
        st.bindings.insert_keeping(
            tok,
            then.clone(),
            payer,
            |b| !b.confirmed() && now.saturating_sub(b.used_ms) > binding::UNCONFIRMED_LIFE_MS,
            Binding::confirmed,
            |b| b.used_ms,
        );
        st.dirty = true;
        if meaningful {
            st.ver += 1;
            let c = saved::change(st.ver, &tok, &payer, Some(&then));
            return self.journal(st, &c);
        }
        Ok(())
    }

    fn journal(&self, st: &mut State, c: &[u8]) -> std::result::Result<(), ()> {
        if let Some(j) = st.journal.as_mut()
            && let Err(e) = j.append(c)
        {
            (self.cfg.log)(&format!("cbb-push: cannot keep a binding: {e}"));
            return Err(());
        }
        Ok(())
    }

    /// Handles one `push/send`.
    fn send(&self, tag: &[u8; 32], face: &[u8; 16], payer: Payer, s: &push::Send<'_>) -> Answer {
        let Some(platform) = self.cfg.platforms.get(&s.env).cloned() else { return refused(push::SENT_FAILED) };
        let at = Instant::now();
        let now = now_ms();
        let budgets = self.cfg.budgets;
        // Every send costs its tag's budget, before any check.
        {
            let mut st = self.lock();
            let Some(p) = st.periods.get_mut(tag) else { return answer(push::SENT_FAILED, None) };
            if p.expires_ms <= now {
                // The credentials expired while connected: a new hello.
                return answer(push::SENT_FAILED, Some(1000));
            }
            if let Err(wait) = p.budget.take(budgets.per_tag, at) {
                return answer(push::SENT_BUDGET, Some(wait.as_millis() as u64));
            }
        }
        if !s.sized() || (s.env == push::ENV_UNIFIEDPUSH && push::UnifiedPush::read(s.token).is_err()) {
            return refused(push::SENT_FAILED);
        }
        match push::check_send(&s.key, s.sig, &s.signed(face)) {
            Ok(push::SendCheck::Good) => {}
            Ok(push::SendCheck::Unknown) => return refused(push::SENT_KEY),
            Err(_) => return refused(push::SENT_STALE),
        }
        let tok = self.keyed(b"token", &s.env.to_be_bytes(), s.token);
        let repeat = self.keyed(b"body", &tok, s.body);
        let key = s.key.hash().0;
        let ask = Ask { key, slot: s.slot, seq: s.seq, challenge: s.challenge };
        // One read of the clock for a binding this send makes: the
        // challenge sent with it and the binding filed after the platform
        // answered are of the same generation.
        let born = binding::clock_generation(now);
        let life_s = push::life_s(s.ttl);
        let expires_s = now / 1000 + life_s;
        let plan = {
            let mut st = self.lock();
            if st.in_flight.contains(&repeat) {
                return answer(push::SENT_FAILED, Some(IN_FLIGHT_WAIT_MS));
            }
            let mut upgrade = false;
            if let Some(r) = st.repeats.get(&repeat)
                && at.saturating_duration_since(r.at) < REPEAT_FOR
            {
                // Sent before; a longer life than that one passes once.
                if life_s <= r.life_s || r.upgraded {
                    return answer(push::SENT_REPEAT, None);
                }
                upgrade = true;
            }
            let mint = |k: &[u8; 32], g: u32, p: u64| self.challenge(&tok, k, g, p);
            let confirmed = st.bindings.get(&tok).is_some_and(Binding::confirmed);
            let verdict = binding::judge(st.bindings.get(&tok), &ask, now, born, &mint);
            // The group's budgets toward this token.
            let tb = self.keyed(b"token-tag", &tok, tag);
            if st.tokens.get(&tb).is_none() {
                let fresh = TokenBudget {
                    send: Bucket::full(budgets.per_token.1, at),
                    unconfirmed: Bucket::full(budgets.unconfirmed.1, at),
                    challenge: Bucket::full(budgets.challenges.1, at),
                };
                st.tokens
                    .insert(tb, fresh, payer, |b| at.saturating_duration_since(b.send.at) > Duration::from_secs(3600));
            }
            if st.ceilings.get(&tok).is_none() {
                let fresh = Ceiling {
                    unconfirmed: Bucket::full(budgets.unconfirmed_token.1, at),
                    confirmed: Bucket::full(budgets.per_token_all.1, at),
                };
                st.ceilings.insert(tok, fresh, payer, |c| {
                    at.saturating_duration_since(c.unconfirmed.at.max(c.confirmed.at)) > Duration::from_secs(3600)
                });
            }
            let Some(b) = st.tokens.get_mut(&tb) else { return answer(push::SENT_BUDGET, Some(60_000)) };
            match verdict {
                Verdict::Stale => return refused(push::SENT_STALE),
                Verdict::Ahead => return refused(push::SENT_AHEAD),
                Verdict::Challenge { value } => {
                    if b.challenge.take(budgets.challenges, at).is_err() {
                        return refused(push::SENT_STALE);
                    }
                    Plan::Challenge { value, answer: refused(push::SENT_STALE), file: None }
                }
                Verdict::Pass { challenge, confirms, .. } if confirmed || confirms => {
                    // The group's rate, then one ceiling for every group
                    // together: a holder of one registration gains nothing
                    // from groups of its own making (the signature names the
                    // face as well).
                    if let Err(wait) = b.send.take(budgets.per_token, at) {
                        return answer(push::SENT_BUDGET, Some(wait.as_millis() as u64));
                    }
                    let all = st
                        .ceilings
                        .get_mut(&tok)
                        .map_or(Err(Duration::from_secs(60)), |c| c.confirmed.take(budgets.per_token_all, at));
                    if let Err(wait) = all {
                        return answer(push::SENT_BUDGET, Some(wait.as_millis() as u64));
                    }
                    st.in_flight.insert(repeat);
                    Plan::Body { repeat, upgrade, challenge }
                }
                Verdict::Pass { challenge, .. } => {
                    // No key confirmed: a small rate per group, and one ceiling
                    // for every group together. Past the ceiling a group that
                    // sent nothing to this token lately (its own rate full)
                    // still sends one body: the phone's own group, which
                    // sends seldom, is not the one that waits behind groups
                    // that keep the ceiling spent. Those quiet passes are
                    // counted per payer and token at the group's rate, so
                    // groups of one maker's making share one. Any other send
                    // carries its challenge alone, so that a flood of other
                    // groups never keeps the phone from confirming.
                    let quiet = b.unconfirmed.full_at(budgets.unconfirmed, at);
                    if let Err(wait) = b.unconfirmed.take(budgets.unconfirmed, at) {
                        return answer(push::SENT_BUDGET, Some(wait.as_millis() as u64));
                    }
                    let ceiling = st
                        .ceilings
                        .get_mut(&tok)
                        .map_or(Err(Duration::from_secs(60)), |c| c.unconfirmed.take(budgets.unconfirmed_token, at));
                    let ceiling = match ceiling {
                        Err(wait) if quiet => {
                            let qk = self.keyed(b"quiet", &payer, &tok);
                            if st.quiet.get(&qk).is_none() {
                                st.quiet.insert(qk, Bucket::full(budgets.unconfirmed.1, at), payer, |q| {
                                    q.full_at(budgets.unconfirmed, at)
                                });
                            }
                            st.quiet
                                .get_mut(&qk)
                                .map_or(Err(wait), |q| q.take(budgets.unconfirmed, at).map_err(|_| wait))
                        }
                        other => other,
                    };
                    match ceiling {
                        Ok(()) => {
                            st.in_flight.insert(repeat);
                            Plan::Body { repeat, upgrade, challenge }
                        }
                        Err(wait) => {
                            let wait = wait.as_millis() as u64;
                            let b = st.tokens.get_mut(&tb).map(|b| b.challenge.take(budgets.challenges, at).is_ok());
                            match (challenge, b) {
                                (Some(value), Some(true)) => Plan::Challenge {
                                    value,
                                    answer: answer(push::SENT_BUDGET, Some(wait)),
                                    file: Some(ask),
                                },
                                _ => return answer(push::SENT_BUDGET, Some(wait)),
                            }
                        }
                    }
                }
            }
        };
        let hint = |v: [u8; 16]| {
            let mut k = [0u8; 8];
            k.copy_from_slice(&key[..8]);
            Challenge { value: v, key: k }
        };
        match plan {
            Plan::Challenge { value, answer: then, file } => {
                let d = Delivery {
                    env: s.env,
                    token: s.token,
                    body: None,
                    challenge: Some(hint(value)),
                    expires_s: now / 1000 + 86_400,
                    tag: *tag,
                };
                // A challenge is computed again, not kept. A token with no
                // binding yet gets one filed once its challenge went, so that
                // the generation the challenge was made for stays.
                if platform.send(&d) == Outcome::Sent
                    && let Some(a) = file
                {
                    let mut st = self.lock();
                    if st.bindings.get(&tok).is_none() && self.commit(&mut st, tok, payer, &a, born).is_err() {
                        return answer(push::SENT_FAILED, Some(JOURNAL_WAIT_MS));
                    }
                }
                then
            }
            Plan::Body { repeat, upgrade, challenge } => {
                let d = Delivery {
                    env: s.env,
                    token: s.token,
                    body: Some(s.body),
                    challenge: challenge.map(hint),
                    expires_s,
                    tag: *tag,
                };
                let out = platform.send(&d);
                let mut st = self.lock();
                st.in_flight.remove(&repeat);
                match out {
                    Outcome::Sent => {
                        self.sent.fetch_add(1, Ordering::Relaxed);
                        let r = Repeat { at, life_s, upgraded: upgrade };
                        st.repeats.insert(repeat, r, payer, |r| at.saturating_duration_since(r.at) >= REPEAT_FOR);
                        match self.commit(&mut st, tok, payer, &ask, born) {
                            Ok(()) => answer(push::SENT, None),
                            Err(()) => answer(push::SENT_FAILED, Some(JOURNAL_WAIT_MS)),
                        }
                    }
                    Outcome::Gone => {
                        if st.bindings.remove(&tok).is_some() {
                            st.dirty = true;
                            st.ver += 1;
                            let c = saved::change(st.ver, &tok, &payer, None);
                            if self.journal(&mut st, &c).is_err() {
                                return answer(push::SENT_FAILED, Some(JOURNAL_WAIT_MS));
                            }
                        }
                        answer(push::SENT_GONE, None)
                    }
                    Outcome::Later(d) => answer(push::SENT_FAILED, Some(d.as_millis() as u64)),
                    Outcome::NoPath => answer(push::SENT_FAILED, None),
                }
            }
        }
    }

    /// Writes the snapshot when the bindings changed, then starts the
    /// journal anew with the changes made meanwhile.
    fn save(&self) {
        let Some(path) = &self.cfg.state else { return };
        let _one = self.saving.lock().unwrap_or_else(|e| e.into_inner());
        let (bytes, at) = {
            let mut st = self.lock();
            if !st.dirty {
                return;
            }
            st.dirty = false;
            let all: Vec<(&[u8; 32], &Binding, Payer)> = st.bindings.iter().collect();
            let bytes = saved::snapshot(&self.secret, st.ver, &all);
            (bytes, st.journal.as_ref().map_or(0, saved::Journal::len))
        };
        if let Err(e) = crate::files::write_atomic(path, &bytes, 0o600) {
            self.lock().dirty = true;
            (self.cfg.log)(&format!("cbb-push: cannot keep the bindings: {e}"));
            return;
        }
        let mut st = self.lock();
        let tail = match st.journal.as_ref().map(|j| j.since(at)) {
            Some(Ok(t)) => t,
            Some(Err(e)) => {
                (self.cfg.log)(&format!("cbb-push: cannot read the journal: {e}"));
                return;
            }
            None => Vec::new(),
        };
        match saved::Journal::start(path, &tail) {
            Ok(j) => st.journal = Some(j),
            Err(e) => (self.cfg.log)(&format!("cbb-push: cannot start the journal: {e}")),
        }
    }

    fn serve(self: &Arc<Self>, tcp: TcpStream, payer: Payer, hello: &mut bool) -> Result<()> {
        tcp.set_read_timeout(Some(HELLO_WAIT)).context("timeout")?;
        tcp.set_write_timeout(Some(HELLO_WAIT)).context("timeout")?;
        let conn = ServerConnection::new(self.tls.clone()).context("TLS")?;
        let mut s = StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock).context("TLS handshake")?;
        }
        let key = s
            .conn
            .peer_certificates()
            .and_then(|c| c.first())
            .and_then(|c| cbb_core::certs::Cert::parse(c.as_ref()).ok())
            .map(|c| c.public_key().to_vec())
            .ok_or_else(|| Error::msg("no client certificate"))?;
        let first = read_frame(&mut s)?;
        let m = frame::read(&first, MAX_FRAME).map_err(|r| Error::msg(r.name()))?;
        let creds: Vec<Vec<u8>> = match (m.t, m.map.get(2)) {
            (push::T_HELLO, Some(Value::Array(a))) if cbb_core::msg::check_map(&push::HELLO, &m.map).is_ok() => {
                a.iter().map(Value::encode).collect()
            }
            _ => return write_frame(&mut s, &push::error("the first message is push/hello")),
        };
        let refs: Vec<&[u8]> = creds.iter().map(Vec::as_slice).collect();
        let (tag, face) = match self.hello(&refs, &key, now_ms(), payer) {
            Ok(t) => t,
            Err(why) => return write_frame(&mut s, &push::error(why)),
        };
        let left = {
            let mut st = self.lock();
            unready_done(&mut st, payer);
            *hello = true;
            st.periods.get(&tag).map_or(0, |p| p.budget.left as u64)
        };
        write_frame(&mut s, &push::ready(left))?;
        s.sock.set_read_timeout(Some(IDLE)).context("timeout")?;
        let mut refusals = 0u32;
        while !self.stop.load(Ordering::Relaxed) {
            let Ok(f) = read_frame(&mut s) else { return Ok(()) };
            let Ok(m) = frame::read(&f, MAX_FRAME) else {
                return write_frame(&mut s, &push::error("not a frame of the format"));
            };
            if m.t != push::T_SEND {
                continue;
            }
            let Ok(send) = push::Send::read(&m.map) else {
                return write_frame(&mut s, &push::error("push/send does not follow its table"));
            };
            let a = self.send(&tag, &face, payer, &send);
            write_frame(&mut s, &push::sent(send.n, a.status, a.retry))?;
            if a.refused {
                refusals += 1;
                if refusals >= REFUSALS_MAX {
                    return write_frame(&mut s, &push::error("too many refused sends"));
                }
            }
        }
        Ok(())
    }
}

/// The connection said hello: it no longer counts among the payer's
/// unready ones.
fn unready_done(st: &mut State, payer: Payer) {
    if let Some(n) = st.unready.get_mut(&payer) {
        *n -= 1;
        if *n == 0 {
            st.unready.remove(&payer);
        }
    }
}

fn read_frame(s: &mut impl Read) -> Result<Vec<u8>> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).context("read")?;
    let n = frame::length(h, MAX_FRAME).map_err(|r| Error::msg(r.name()))?;
    let mut f = vec![0u8; n + 4];
    f[..4].copy_from_slice(&h);
    s.read_exact(&mut f[4..]).context("read")?;
    Ok(f)
}

fn write_frame(s: &mut impl Write, f: &[u8]) -> Result<()> {
    s.write_all(f).and_then(|()| s.flush()).context("write")
}

impl Service {
    pub fn start(cfg: Config) -> Result<Service> {
        let clock: cbb_core::tls::Clock = Arc::new(crate::forward::SystemClock);
        let tls = cbb_core::tls::registration_server(&cfg.cert, &cfg.key, push::ALPN, &clock)?;
        let loaded = match &cfg.state {
            Some(path) => saved::load(path, cfg.new_state)?,
            None => saved::Loaded { secret: cbb_core::certs::random_bytes(), ver: 0, bindings: HashMap::new() },
        };
        let tcp = TcpListener::bind(cfg.listen).context(format!("cannot listen on {}", cfg.listen))?;
        let addr = tcp.local_addr().context("cannot listen")?;
        let now = now_ms();
        let mut bindings = Shared::new(BINDINGS_MAX);
        for (tok, (mut b, payer)) in loaded.bindings {
            // A time written while the clock was ahead is read as now.
            b.clamp(now);
            bindings.insert(tok, b, payer, |_| false);
        }
        let state = State {
            periods: HashMap::new(),
            tokens: Shared::new(TOKENS_MAX),
            ceilings: Shared::new(TOKENS_MAX),
            quiet: Shared::new(TOKENS_MAX),
            repeats: Shared::new(REPEATS_MAX),
            bindings,
            in_flight: HashSet::new(),
            dirty: cfg.state.is_some(),
            ver: loaded.ver,
            journal: None,
            connections: 0,
            per_payer: HashMap::new(),
            unready: HashMap::new(),
            new_tags: HashMap::new(),
        };
        let inner = Arc::new(Inner {
            cfg,
            tls: Arc::new(tls),
            secret: loaded.secret,
            state: Mutex::new(state),
            saving: Mutex::new(()),
            stop: AtomicBool::new(false),
            sent: AtomicU64::new(0),
        });
        // The snapshot (with the secret) and a fresh journal before the
        // first send.
        if let Some(path) = &inner.cfg.state {
            let bytes = {
                let st = inner.lock();
                let all: Vec<(&[u8; 32], &Binding, Payer)> = st.bindings.iter().collect();
                saved::snapshot(&inner.secret, st.ver, &all)
            };
            crate::files::write_atomic(path, &bytes, 0o600)?;
            let j = saved::Journal::start(path, &[])?;
            let mut st = inner.lock();
            st.journal = Some(j);
            st.dirty = false;
        }
        let accept = inner.clone();
        std::thread::Builder::new()
            .name("cbb-push accept".into())
            .spawn(move || accept.accept(tcp))
            .context("cannot start the service")?;
        let saver = inner.clone();
        std::thread::Builder::new()
            .name("cbb-push saver".into())
            .spawn(move || {
                while !saver.stop.load(Ordering::Relaxed) {
                    std::thread::sleep(SAVE_EVERY);
                    saver.save();
                }
            })
            .context("cannot start the service")?;
        Ok(Service { inner, addr })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Counts for the log: tags held, tokens held, bodies sent.
    pub fn stats(&self) -> (usize, usize, u64) {
        let st = self.inner.lock();
        (st.periods.len(), st.tokens.len(), self.inner.sent.load(Ordering::Relaxed))
    }

    /// Bindings held.
    pub fn bindings(&self) -> usize {
        self.inner.lock().bindings.len()
    }

    /// Stops the service and writes its bindings.
    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
        self.inner.lock().dirty = true;
        self.inner.save();
    }
}

impl Inner {
    fn accept(self: Arc<Self>, tcp: TcpListener) {
        for c in tcp.incoming() {
            if self.stop.load(Ordering::Relaxed) {
                return;
            }
            let Ok(c) = c else { continue };
            let ip = c.peer_addr().map_or(IpAddr::from([0u8; 4]), |a| a.ip());
            let payer = self.payer(ip);
            {
                let mut st = self.lock();
                let b = self.cfg.budgets;
                let here = st.per_payer.get(&payer).copied().unwrap_or(0);
                let waiting = st.unready.get(&payer).copied().unwrap_or(0);
                if st.connections >= b.connections || here >= b.per_address || waiting >= b.unready {
                    continue;
                }
                st.connections += 1;
                *st.per_payer.entry(payer).or_default() += 1;
                *st.unready.entry(payer).or_default() += 1;
            }
            let me = self.clone();
            let release = move |me: &Inner, hello_done: bool| {
                let mut st = me.lock();
                st.connections -= 1;
                if let Some(n) = st.per_payer.get_mut(&payer) {
                    *n -= 1;
                    if *n == 0 {
                        st.per_payer.remove(&payer);
                    }
                }
                if !hello_done {
                    unready_done(&mut st, payer);
                }
            };
            let spawned = std::thread::Builder::new().name("cbb-push conn".into()).spawn(move || {
                // serve takes the connection off the payer's unready ones
                // once its hello passed; otherwise it is done here.
                let mut hello = false;
                let _ = me.serve(c, payer, &mut hello);
                release(&me, hello);
            });
            if spawned.is_err() {
                release(&self, false);
            }
        }
    }
}
