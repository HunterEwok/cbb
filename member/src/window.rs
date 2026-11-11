// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A pairing window on an admin (cbb pair): a six-digit code a joining
//! device dials the member port with, as Go's pair.Window
//! (docs/protocol.md, section 6). One attempt runs at a time, three that
//! fail close the window, and it closes after LIFETIME or once it admitted
//! a device. Sending the Welcome is the point of no return: the device
//! counts as admitted from then on, whatever it answers.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use cbb_core::admit::{self, Admission, Admitter, Outcome};
use cbb_core::pair::{MAX_FAILURES, Refusal};

use crate::error::{Context, Error, Result};
use crate::node::Node;
use crate::tls;
use crate::uptime;

/// How long a window stays open, counting the time the machine sleeps; an
/// attempt that has started may finish after it.
pub const LIFETIME: Duration = Duration::from_secs(300);
/// How long one attempt may take.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the joiner has for its first message once it holds the
/// window's one attempt.
const FIRST_TIMEOUT: Duration = Duration::from_secs(10);
/// How many attempts from one address may end before they count; the
/// window refuses that address as busy afterwards.
const MAX_IDLE: u32 = 5;
/// How long a refused joiner has for its first message.
const REFUSE_TIMEOUT: Duration = Duration::from_secs(10);

/// The device a window admitted.
pub struct Joined {
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code))]
    pub device: String,
    pub name: String,
    /// Whether it said that it stored its identity.
    pub confirmed: bool,
}

#[derive(Default)]
struct State {
    expires: Duration, // on the uptime clock
    busy: bool,
    committed: bool,
    /// close came while committed: the window closes if the attempt fails.
    closing: bool,
    failures: u32,
    idle: HashMap<IpAddr, u32>,
    /// The running attempt's socket, which close shuts.
    running: Option<TcpStream>,
    /// How the window ended, once it has.
    end: Option<std::result::Result<Joined, Refusal>>,
}

/// Asked whether to admit a device that proved it knows a remote
/// invitation's secret, as Go's pair.Options.Confirm; it may take up to
/// CONFIRM_WAIT for the admin's answer, and a no declines the device.
pub type Confirm = Box<dyn Fn(&admit::Request) -> bool + Send + Sync>;

/// How long a window waits for its admin to confirm a device that used an
/// invitation, as Go's confirmWait.
pub const CONFIRM_WAIT: Duration = crate::pair::CONFIRM_WAIT;

/// An open pairing window.
pub struct Window {
    admitter: Admitter,
    code: String,
    /// A remote invitation's secret, in place of the code, and who
    /// confirms the device that proves it.
    secret: Option<(Vec<u8>, Confirm)>,
    state: Mutex<State>,
    changed: Condvar,
}

impl Window {
    /// Opens a window with code on the admitter.
    pub fn open(admitter: Admitter, code: &str) -> Result<Arc<Window>> {
        let code = cbb_core::pair::normalize_code(code)?;
        let state = State { expires: uptime::now() + LIFETIME, ..Default::default() };
        Ok(Arc::new(Window { admitter, code, secret: None, state: Mutex::new(state), changed: Condvar::new() }))
    }

    /// Opens a remote invitation's window on the admitter, for lifetime:
    /// its secret in place of a code, and confirm asked about the device
    /// that proves it (docs/design.md, "Joining from another network").
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code))]
    pub fn open_secret(admitter: Admitter, secret: &[u8], lifetime: Duration, confirm: Confirm) -> Result<Arc<Window>> {
        if secret.len() < cbb_core::pair::MIN_SECRET {
            return Err(Error::msg("the invitation's secret is too short"));
        }
        let state = State { expires: uptime::now() + lifetime, ..Default::default() };
        Ok(Arc::new(Window {
            admitter,
            code: String::new(),
            secret: Some((secret.to_vec(), confirm)),
            state: Mutex::new(state),
            changed: Condvar::new(),
        }))
    }

    /// The window's code, six digits.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Closes the window. A running attempt fails at once, unless it has
    /// started sending the Welcome; the device is admitted then.
    pub fn close(&self) {
        let mut st = self.state.lock().unwrap();
        if st.end.is_some() {
            return;
        }
        if st.committed {
            // succeed closes the window, or release if the attempt fails.
            st.closing = true;
            return;
        }
        st.end = Some(Err(Refusal::Closed));
        if let Some(s) = st.running.take() {
            let _ = s.shutdown(Shutdown::Both);
        }
        self.changed.notify_all();
    }

    /// Waits until the window ends, and returns the device it admitted or
    /// why it closed; stop is asked every second, and closes it when true.
    pub fn wait(&self, stop: &dyn Fn() -> bool) -> std::result::Result<Joined, Refusal> {
        let mut st = self.state.lock().unwrap();
        loop {
            if let Some(end) = st.end.take() {
                // A second wait sees the window closed.
                st.end = Some(Err(Refusal::Closed));
                return end;
            }
            if !st.busy && uptime::now() >= st.expires {
                st.end = Some(Err(Refusal::Expired));
                continue;
            }
            if stop() {
                drop(st);
                self.close();
                st = self.state.lock().unwrap();
                // An attempt sending the Welcome ends first.
                if st.end.is_some() {
                    continue;
                }
            }
            st = self.changed.wait_timeout(st, Duration::from_secs(1)).unwrap().0;
        }
    }

    /// Starts an attempt from addr, or says why the window takes none.
    fn acquire(&self, sock: &TcpStream, addr: IpAddr) -> std::result::Result<(), Refusal> {
        let mut st = self.state.lock().unwrap();
        if st.end.is_none() && !st.busy && uptime::now() >= st.expires {
            st.end = Some(Err(Refusal::Expired));
            self.changed.notify_all();
        }
        match &st.end {
            Some(Ok(_)) => return Err(Refusal::Closed),
            Some(Err(why)) => return Err(*why),
            None => {}
        }
        if st.busy || st.idle.get(&addr).copied().unwrap_or(0) >= MAX_IDLE {
            return Err(Refusal::Busy);
        }
        st.busy = true;
        st.running = sock.try_clone().ok();
        Ok(())
    }

    /// Marks the running attempt as admitted, just before the Welcome goes
    /// out, unless the window was closed meanwhile.
    fn commit(&self) -> bool {
        let mut st = self.state.lock().unwrap();
        if st.end.is_some() {
            return false;
        }
        st.committed = true;
        true
    }

    /// Ends an attempt that admitted no device; failed tells whether it
    /// counts. One that does not still counts against its address, so that
    /// one device cannot keep the window busy.
    fn release(&self, failed: bool, addr: IpAddr) {
        let mut st = self.state.lock().unwrap();
        st.busy = false;
        st.running = None;
        if std::mem::take(&mut st.committed) && st.closing && st.end.is_none() {
            st.end = Some(Err(Refusal::Closed));
        }
        if failed {
            st.failures += 1;
            if st.failures >= MAX_FAILURES && st.end.is_none() {
                st.end = Some(Err(Refusal::TooMany));
            }
        } else if st.end.is_none() && st.idle.len() < 1024 {
            *st.idle.entry(addr).or_default() += 1;
        }
        if st.end.is_none() && uptime::now() >= st.expires {
            st.end = Some(Err(Refusal::Expired));
        }
        self.changed.notify_all();
    }

    /// Records the admitted device and closes the window.
    fn succeed(&self, j: Joined) {
        let mut st = self.state.lock().unwrap();
        st.busy = false;
        st.committed = false;
        st.running = None;
        st.end = Some(Ok(j));
        self.changed.notify_all();
    }

    /// Serves a pairing connection a joiner dialed, whose handshake is
    /// done (Node::on_pairing): one attempt, whose result the window keeps.
    pub fn serve(
        &self,
        node: &Node,
        sock: TcpStream,
        session: tls::Session,
        exporter: Arc<tls::Exporter>,
        addr: SocketAddr,
    ) -> Result<()> {
        if let Err(why) = self.acquire(&sock, addr.ip()) {
            refuse(sock, session, why);
            return Err(Error::with(format!("pair: {}", why), why));
        }
        let view = admit::GroupView::of(&node.records().lock().unwrap());
        // The identity the handshake just presented: a certificate renewed
        // since the window opened (an admin's, made one moments before)
        // would otherwise bind the pairing to the old one, and the joiner's
        // check would fail as a wrong code.
        let mut admitter = self.admitter.clone();
        admitter.identity = (*node.identity()).clone();
        let res = match &self.secret {
            Some((secret, _)) => Admission::accept_secret(admitter, view, secret, session, exporter),
            None => Admission::accept(admitter, view, &self.code, session, exporter),
        };
        let mut adm = match res {
            Ok(a) => a,
            Err(e) => {
                self.release(false, addr.ip());
                return Err(e);
            }
        };
        let mut name = None;
        let res = self.attempt(node, &mut adm, &sock, &mut name);
        let _ = sock.shutdown(Shutdown::Both);
        match (res, name) {
            (Ok(confirmed), Some((device, name))) => {
                self.succeed(Joined { device, name: name.clone(), confirmed });
                if confirmed {
                    Ok(())
                } else {
                    Err(Error::msg(format!("{name} got its certificate but did not confirm that it stored it")))
                }
            }
            (Err(e), Some((device, name))) => {
                self.succeed(Joined { device, name, confirmed: false });
                Err(e)
            }
            (Ok(_), None) => {
                self.release(adm.started(), addr.ip());
                Err(Error::msg("the pairing ended early"))
            }
            (Err(e), None) => {
                // A window closed under the attempt is not the joiner's doing.
                let closed = matches!(self.state.lock().unwrap().end, Some(Err(Refusal::Closed)));
                self.release(adm.started() && !closed, addr.ip());
                Err(e)
            }
        }
    }

    /// Runs the exchange; name is set once the device is admitted. Returns
    /// whether the device confirmed that it stored its identity.
    fn attempt(
        &self,
        node: &Node,
        adm: &mut Admission,
        sock: &TcpStream,
        name: &mut Option<(String, String)>,
    ) -> Result<bool> {
        let wait = if self.secret.is_some() { CONFIRM_WAIT } else { Duration::ZERO };
        let end = Instant::now() + ATTEMPT_TIMEOUT + wait;
        let first = Instant::now() + FIRST_TIMEOUT;
        let mut sock = sock;
        let mut input: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 16 << 10];
        loop {
            let mut step = adm.feed(&input, uptime::wall_ms());
            if let (Outcome::Confirm(r), Some((_, confirm))) = (&step.outcome, &self.secret) {
                // The joiner waits while the admin is asked.
                if !step.send.is_empty() {
                    sock.write_all(&step.send).context("cannot send to the device")?;
                }
                let yes = confirm(r);
                if !yes {
                    (crate::service::log_line)(&format!(
                        "cbb: the admin did not confirm {} ({}), which used an invitation",
                        r.name, r.device
                    ));
                }
                step = adm.answer(yes, uptime::wall_ms());
            }
            match step.outcome {
                Outcome::Pending => {}
                Outcome::Confirm(_) => return Err(Error::msg("a window with a code asks no admin")),
                Outcome::Admitted(a) => {
                    if !self.commit() {
                        return Err(Error::with(format!("pair: {}", Refusal::Closed), Refusal::Closed));
                    }
                    // From here on the device counts as admitted: the
                    // Welcome may reach it even if this side sees an error.
                    *name = Some((a.device.to_string(), a.info.name.clone()));
                    let how = if self.secret.is_some() { "with an invitation" } else { "by its code" };
                    crate::admin::record_admitted(node, &self.admitter, &a, how)?;
                }
                Outcome::Done { confirmed } => {
                    let _ = sock.write_all(&step.send);
                    return Ok(confirmed);
                }
                Outcome::Failed { error, wrong_code } => {
                    let _ = sock.write_all(&step.send);
                    return Err(if wrong_code {
                        Error::with(format!("pair: {}", Refusal::WrongCode), Refusal::WrongCode)
                    } else {
                        error
                    });
                }
            }
            if !step.send.is_empty() {
                sock.write_all(&step.send).context("cannot send to the device")?;
            }
            // The joiner's first message comes soon, or it gives up the
            // window's one attempt.
            let by = if adm.started() { end } else { end.min(first) };
            let left = by.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::msg("the device did not finish pairing in time"));
            }
            sock.set_read_timeout(Some(left)).context("cannot read from the device")?;
            let n = sock.read(&mut buf).context("cannot read from the device")?;
            if n == 0 {
                return Err(Error::msg("the device closed the connection"));
            }
            input = buf[..n].to_vec();
        }
    }
}

/// Answers a joiner's first frame with why no window takes its attempt,
/// and closes the connection; the joiner sees why, not a broken
/// connection.
pub fn refuse(sock: TcpStream, mut session: tls::Session, why: Refusal) {
    let _ = sock.set_read_timeout(Some(REFUSE_TIMEOUT));
    let mut s = &sock;
    let (mut plain, mut buf, mut got) = (Vec::new(), vec![0u8; 16 << 10], [0u8; 4096]);
    loop {
        loop {
            let n = session.read(&mut got);
            if n == 0 {
                break;
            }
            plain.extend_from_slice(&got[..n]);
        }
        let whole = plain.get(..4).map(|h| u32::from_be_bytes([h[0], h[1], h[2], h[3]]) as usize + 4);
        if whole.is_some_and(|w| plain.len() >= w) {
            break;
        }
        match s.read(&mut buf) {
            Ok(n) if n > 0 => {
                if session.feed(&buf[..n]).is_err() {
                    return;
                }
                let _ = tls::flush(&mut session, &sock);
            }
            _ => return,
        }
    }
    let _ = session.write(&admit::refusal_frame(why));
    let _ = session.close();
    let _ = tls::flush(&mut session, &sock);
    let _ = sock.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    fn admitter() -> Admitter {
        let dir =
            std::env::temp_dir().join(format!("cbb-window-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (ident, _) = crate::admin::new_group(&dir, "desk").unwrap();
        let s = crate::admin::signer(&dir, &ident).unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        Admitter { identity: ident, ca: s.ca, ca_key: s.key, make_admins: false }
    }

    /// A connected socket, which acquire keeps for close to shut.
    fn sock() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        (a, l.accept().unwrap().0)
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    fn joined() -> Joined {
        Joined { device: "d".into(), name: "phone".into(), confirmed: true }
    }

    fn ends(w: &Window) -> Option<std::result::Result<String, Refusal>> {
        w.state.lock().unwrap().end.as_ref().map(|e| e.as_ref().map(|j| j.name.clone()).map_err(|r| *r))
    }

    #[test]
    fn opens_for_its_lifetime() {
        let w = Window::open(admitter(), "123-456").unwrap();
        assert_eq!(w.code(), "123456");
        let left = w.state.lock().unwrap().expires.saturating_sub(uptime::now());
        assert!(left > LIFETIME - Duration::from_secs(5) && left <= LIFETIME, "{left:?}");
        assert!(Window::open(admitter(), "12345").is_err());

        let short = vec![7u8; cbb_core::pair::MIN_SECRET - 1];
        assert!(Window::open_secret(admitter(), &short, LIFETIME, Box::new(|_| true)).is_err());
        let secret = vec![7u8; cbb_core::pair::MIN_SECRET];
        let w = Window::open_secret(admitter(), &secret, Duration::from_secs(60), Box::new(|_| true)).unwrap();
        let left = w.state.lock().unwrap().expires.saturating_sub(uptime::now());
        assert!(left > Duration::from_secs(55) && left <= Duration::from_secs(60), "{left:?}");
    }

    #[test]
    fn one_attempt_at_a_time_and_few_from_one_address() {
        let w = Window::open(admitter(), "123456").unwrap();
        let (s, _peer) = sock();
        assert_eq!(w.acquire(&s, ip(1)), Ok(()));
        assert!(w.state.lock().unwrap().running.is_some());
        assert_eq!(w.acquire(&s, ip(2)), Err(Refusal::Busy));
        w.release(false, ip(1));
        assert!(w.state.lock().unwrap().running.is_none());
        // Attempts that end before they count still count against their
        // address, up to MAX_IDLE.
        for _ in 1..MAX_IDLE {
            assert_eq!(w.acquire(&s, ip(1)), Ok(()));
            w.release(false, ip(1));
        }
        assert_eq!(w.state.lock().unwrap().idle.get(&ip(1)), Some(&MAX_IDLE));
        assert_eq!(w.acquire(&s, ip(1)), Err(Refusal::Busy));
        assert_eq!(w.acquire(&s, ip(2)), Ok(()));
        w.release(false, ip(2));
        assert_eq!(ends(&w), None);
    }

    #[test]
    fn failures_close_it() {
        let w = Window::open(admitter(), "123456").unwrap();
        let (s, _peer) = sock();
        for _ in 1..MAX_FAILURES {
            w.acquire(&s, ip(1)).unwrap();
            w.release(true, ip(1));
            assert_eq!(ends(&w), None);
        }
        w.acquire(&s, ip(1)).unwrap();
        w.release(true, ip(1));
        assert_eq!(ends(&w), Some(Err(Refusal::TooMany)));
        assert_eq!(w.acquire(&s, ip(3)), Err(Refusal::TooMany));
        assert!(w.wait(&|| false).is_err_and(|r| r == Refusal::TooMany));
        // A second wait sees it closed.
        assert!(w.wait(&|| false).is_err_and(|r| r == Refusal::Closed));
    }

    #[test]
    fn close_stops_an_attempt_unless_it_committed() {
        let w = Window::open(admitter(), "123456").unwrap();
        let (s, mut peer) = sock();
        w.acquire(&s, ip(1)).unwrap();
        w.close();
        assert_eq!(ends(&w), Some(Err(Refusal::Closed)));
        // The running attempt's socket is shut.
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0);
        assert!(!w.commit(), "an attempt commits after close");
        assert_eq!(w.acquire(&s, ip(2)), Err(Refusal::Closed));

        // Committed and not closed: a failure counts as one.
        let w = Window::open(admitter(), "123456").unwrap();
        w.acquire(&s, ip(1)).unwrap();
        assert!(w.commit());
        w.release(true, ip(1));
        assert_eq!(ends(&w), None);
        assert!(!w.state.lock().unwrap().committed);

        // Committed: close waits for the attempt, and a failure then closes.
        let w = Window::open(admitter(), "123456").unwrap();
        w.acquire(&s, ip(1)).unwrap();
        assert!(w.commit());
        w.close();
        assert_eq!(ends(&w), None);
        w.release(true, ip(1));
        assert_eq!(ends(&w), Some(Err(Refusal::Closed)));

        // Committed and closed, but admitted: the device counts.
        let w = Window::open(admitter(), "123456").unwrap();
        w.acquire(&s, ip(1)).unwrap();
        assert!(w.commit());
        w.close();
        w.succeed(joined());
        let st = w.state.lock().unwrap();
        assert!(!st.busy && !st.committed && st.running.is_none());
        drop(st);
        assert_eq!(w.wait(&|| true).map(|j| j.name).ok(), Some("phone".to_string()));
        assert_eq!(w.acquire(&s, ip(1)), Err(Refusal::Closed));
        assert!(!w.commit());
    }

    #[test]
    fn a_window_ends_when_its_time_is_up() {
        let (s, _peer) = sock();
        let w = Window::open(admitter(), "123456").unwrap();
        w.state.lock().unwrap().expires = uptime::now();
        assert_eq!(w.acquire(&s, ip(1)), Err(Refusal::Expired));

        // A running attempt may finish after it, and ends the window then.
        let w = Window::open(admitter(), "123456").unwrap();
        w.acquire(&s, ip(1)).unwrap();
        w.state.lock().unwrap().expires = uptime::now();
        assert_eq!(ends(&w), None);
        w.release(false, ip(1));
        assert_eq!(ends(&w), Some(Err(Refusal::Expired)));

        let w = Window::open(admitter(), "123456").unwrap();
        w.state.lock().unwrap().expires = uptime::now();
        assert!(w.wait(&|| false).is_err_and(|r| r == Refusal::Expired));
    }

    #[test]
    fn wait_closes_it_when_asked() {
        let w = Window::open(admitter(), "123456").unwrap();
        assert!(w.wait(&|| true).is_err_and(|r| r == Refusal::Closed));
        // wait returns what an attempt in another thread ends with.
        let w = Window::open(admitter(), "123456").unwrap();
        let (s, _peer) = sock();
        w.acquire(&s, ip(1)).unwrap();
        let w2 = w.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            w2.succeed(joined());
        });
        assert!(w.wait(&|| false).is_ok());
        t.join().unwrap();
    }
}
