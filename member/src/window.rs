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
    pub name: String,
    /// Whether it said that it stored its identity.
    pub confirmed: bool,
}

#[derive(Default)]
struct State {
    expires: Duration, // on the uptime clock
    busy: bool,
    committed: bool,
    failures: u32,
    idle: HashMap<IpAddr, u32>,
    /// The running attempt's socket, which close shuts.
    running: Option<TcpStream>,
    /// How the window ended, once it has.
    end: Option<std::result::Result<Joined, Refusal>>,
}

/// An open pairing window.
pub struct Window {
    admitter: Admitter,
    code: String,
    state: Mutex<State>,
    changed: Condvar,
}

impl Window {
    /// Opens a window with code on the admitter.
    pub fn open(admitter: Admitter, code: &str) -> Result<Arc<Window>> {
        let code = cbb_core::pair::normalize_code(code)?;
        let state = State { expires: uptime::now() + LIFETIME, ..Default::default() };
        Ok(Arc::new(Window { admitter, code, state: Mutex::new(state), changed: Condvar::new() }))
    }

    /// The window's code, six digits.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Closes the window. A running attempt fails at once, unless it has
    /// started sending the Welcome; the device is admitted then.
    pub fn close(&self) {
        let mut st = self.state.lock().unwrap();
        if st.committed || st.end.is_some() {
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
                continue;
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
            return Err(Error::with("the pairing failed", why));
        }
        let view = admit::GroupView::of(&node.records().lock().unwrap());
        let res = Admission::accept(self.admitter.clone(), view, &self.code, session, exporter);
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
            (Ok(confirmed), Some(name)) => {
                self.succeed(Joined { name: name.clone(), confirmed });
                if confirmed {
                    Ok(())
                } else {
                    Err(Error::msg(format!("{name} got its certificate but did not confirm that it stored it")))
                }
            }
            (Err(e), Some(name)) => {
                self.succeed(Joined { name, confirmed: false });
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
    fn attempt(&self, node: &Node, adm: &mut Admission, sock: &TcpStream, name: &mut Option<String>) -> Result<bool> {
        let end = Instant::now() + ATTEMPT_TIMEOUT;
        let first = Instant::now() + FIRST_TIMEOUT;
        let mut sock = sock;
        let mut input: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 16 << 10];
        loop {
            let step = adm.feed(&input, uptime::wall_ms());
            match step.outcome {
                Outcome::Pending => {}
                Outcome::Admitted(a) => {
                    if !self.commit() {
                        return Err(Error::with("the pairing failed", Refusal::Closed));
                    }
                    // From here on the device counts as admitted: the
                    // Welcome may reach it even if this side sees an error.
                    *name = Some(a.info.name.clone());
                    crate::admin::record_admitted(node, &self.admitter, &a, "by its code")?;
                }
                Outcome::Done { confirmed } => {
                    let _ = sock.write_all(&step.send);
                    return Ok(confirmed);
                }
                Outcome::Failed { error, wrong_code } => {
                    let _ = sock.write_all(&step.send);
                    return Err(if wrong_code { Error::with("the pairing failed", Refusal::WrongCode) } else { error });
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
