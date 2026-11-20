// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member connection of 0.6 on a computer (format section 9): the
//! connections to the group's members over TLS by key (`cbb/4`), and on
//! each the records exchange (`link`), the keys statements (`sealed`),
//! copies, commands and their results. It is built beside the member of
//! 0.5 (`node`) and takes its place when the service switches.
//!
//! Each connection has two threads: the one that dialed or accepted reads,
//! and a writer sends what is queued, and a ping after five seconds of
//! silence. Both use the TLS session under a lock; only the reader waits
//! on the socket without it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use cbb_core::commands::Keys;
use cbb_core::content::Content;
use cbb_core::copies::{self, fresh::Marks};
use cbb_core::format::cbor::Value;
use cbb_core::format::frame;
use cbb_core::hlc::{Clock, Timestamp};
use cbb_core::keystore;
use cbb_core::msg::member as m;
use cbb_core::peer::{Standing, standing};
use cbb_core::records::{DeviceId, Key, RecordSet, State};
use cbb_core::tls::bykey;

use crate::commands::{self, Book};
use crate::content::Store;
use crate::entries::Entries;
use crate::epochs::FileStore;
use crate::error::{Error, Result};
use crate::hello::Hello;
use crate::link::{self, Exchange};
use crate::own::Own;
use crate::releases::Releases;
use crate::sealed::{self, Lifetimes, Statements, Taken};
use crate::tls;
use serde_json::value::RawValue;

const PING_EVERY: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const QUEUE_LEN: usize = 256;
/// The copies' IDs remembered, so each is passed on once.
const SEEN_COPIES: usize = 4096;
/// The marks file's name in the state directory.
pub const MARKS_FILE: &str = "marks.cbor";
/// How long a command's sender waits for its result.
pub const RESULT_WAIT: Duration = Duration::from_secs(30);

/// New content a peer's copy brought.
#[derive(Clone, Debug)]
pub struct Arrived {
    /// The copy's ID.
    pub id: [u8; 16],
    pub content: Content,
    pub origin: DeviceId,
    /// Its age by the core's judgement of freshness.
    pub age_ms: u64,
    /// Its blob of images or files, to fetch (`Mesh::fetch`) and open.
    pub blob: Option<sealed::Blob>,
    /// The member it came from, which holds its blob when it has one.
    pub from: DeviceId,
}

/// New content a peer's copy brought, for the clipboard's engine.
pub type OnCopy = Box<dyn Fn(&Arrived) + Send + Sync>;
/// A command taken here, for the caller to carry out; an error is
/// answered as failed.
pub type OnCommand = Box<dyn Fn(&commands::Taken) -> Result<()> + Send + Sync>;
/// A message the member connection passes to the service: credentials,
/// tunnel, hubs, guest, reach, evidence, waiting and dismiss (its type and
/// body), from the peer named.
pub type OnOther = Box<dyn Fn(&DeviceId, u64, &[u8]) + Send + Sync>;
/// A pairing a device opened on the member port (ALPN `cbb-pair/3`): its
/// socket, the TLS session and the session's pairing exporter, for the
/// pairing window (`join::member`).
pub type OnPair = Box<dyn Fn(TcpStream, tls::Session, cbb_core::join::PairExporter) + Send + Sync>;
/// The set changed (new records came, or this device wrote one).
pub type OnSet = Box<dyn Fn(&RecordSet) + Send + Sync>;

/// The result of a command, as message `result` gave it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandResult {
    pub by: DeviceId,
    /// 1 done, 2 refused, 3 failed.
    pub status: u64,
    pub reason: String,
}

/// A device's member connection of 0.6.
pub struct Mesh {
    own: Own,
    dir: PathBuf,
    local: [u8; 32],
    set: Arc<Mutex<RecordSet>>,
    statements: Mutex<Statements>,
    store: Mutex<FileStore>,
    book: Mutex<Book>,
    marks: Mutex<Marks>,
    kept: Mutex<HashMap<[u8; 16], copies::Kept>>,
    seen: Mutex<Seen>,
    /// The sealed blobs this member made or fetched, which it serves.
    content: Arc<Store>,
    /// The fetches running, by blob.
    fetches: Mutex<HashMap<[u8; 32], SyncSender<media::Got>>>,
    conns: Mutex<HashMap<DeviceId, Arc<Conn>>>,
    /// The last hello of each device connected now, for the views.
    hellos: Mutex<HashMap<DeviceId, Hello>>,
    clock: Clock,
    hello: RwLock<Hello>,
    lifetimes: RwLock<Lifetimes>,
    on_copy: RwLock<Option<OnCopy>>,
    on_command: RwLock<Option<OnCommand>>,
    on_set: RwLock<Option<OnSet>>,
    on_other: RwLock<Option<OnOther>>,
    on_pair: RwLock<Option<OnPair>>,
    waiting: Mutex<HashMap<[u8; 16], SyncSender<CommandResult>>>,
    /// The signed release and entry points this member holds and passes on.
    releases: RwLock<Option<Arc<Releases>>>,
    entries: RwLock<Option<Arc<Entries>>>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    closed: AtomicBool,
}

/// The copies' IDs seen, and their order, to forget the oldest.
type Seen = (HashSet<[u8; 16]>, VecDeque<[u8; 16]>);

struct Conn {
    peer: DeviceId,
    tls: Mutex<tls::Session>,
    sock: TcpStream,
    tx: SyncSender<Vec<u8>>,
    closed: AtomicBool,
    /// The device with the lower ID dialed it.
    lower_dialed: bool,
}

impl Conn {
    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self.sock.shutdown(Shutdown::Both);
        }
    }

    fn write(&self, frame: &[u8]) -> io::Result<()> {
        let mut s = self.tls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        s.write(frame).map_err(|e| io::Error::other(e.for_log()))?;
        tls::flush(&mut s, &self.sock)
    }
}

/// Reads plaintext from a connection, waiting on the socket without the
/// TLS lock.
struct Reader<'a> {
    c: &'a Conn,
    buf: Vec<u8>,
}

impl Read for Reader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            {
                let s = &mut *self.c.tls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let n = s.read(out);
                if n > 0 || out.is_empty() || s.peer_closed() {
                    return Ok(n);
                }
            }
            self.buf.resize(16 << 10, 0);
            let n = (&self.c.sock).read(&mut self.buf).map_err(|e| match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("nothing came for {} s, not even a ping", TIMEOUT.as_secs()),
                ),
                _ => e,
            })?;
            if n == 0 {
                return Ok(0);
            }
            let mut s = self.c.tls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let fed = s.feed(&self.buf[..n]);
            tls::flush(&mut s, &self.c.sock)?;
            fed.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.for_log()))?;
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ping() -> Vec<u8> {
    frame::write(&Value::Map(vec![(frame::FIELD_T, Value::Uint(m::T_PING))]))
}

fn result_frame(id: &[u8; 16], by: &DeviceId, status: u64, reason: &str) -> Vec<u8> {
    let mut f = vec![
        (frame::FIELD_T, Value::Uint(cbb_core::msg::tables::T_RESULT)),
        (2, Value::Bytes(id)),
        (3, Value::Bytes(&by.0)),
        (4, Value::Uint(status)),
    ];
    if !reason.is_empty() {
        f.push((5, Value::Text(reason)));
    }
    frame::write(&Value::Map(f))
}

impl Mesh {
    /// Opens the member of the group kept in dir, with the device's own
    /// keys; an error when the device is in no group.
    pub fn open(dir: &Path, own: Own, log: Arc<dyn Fn(&str) + Send + Sync>) -> Result<Arc<Mesh>> {
        let local = crate::set::local_key(dir)?;
        let set = crate::set::load(dir, &local)?.ok_or_else(|| Error::msg("this device is in no group"))?;
        let store = FileStore::load(dir, &local, own.member.clone())?;
        let marks = match std::fs::read(dir.join(MARKS_FILE)) {
            Ok(b) => Marks::decode(&b).map_err(|r| Error::msg(format!("{MARKS_FILE} is damaged: {r}")))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Marks::default(),
            Err(e) => return Err(Error::with(format!("cannot read {MARKS_FILE}"), e)),
        };
        let clock = Clock::new(Box::new(crate::uptime::wall_ms), Timestamp::default(), None);
        let mesh = Mesh {
            statements: Mutex::new(Statements::load(dir)?),
            book: Mutex::new(Book::load(dir)?),
            store: Mutex::new(store),
            marks: Mutex::new(marks),
            own,
            dir: dir.to_path_buf(),
            local,
            set: Arc::new(Mutex::new(set)),
            kept: Mutex::new(HashMap::new()),
            seen: Mutex::new((HashSet::new(), VecDeque::new())),
            content: Arc::new(Store::open(dir)),
            fetches: Mutex::new(HashMap::new()),
            conns: Mutex::new(HashMap::new()),
            hellos: Mutex::new(HashMap::new()),
            clock,
            hello: RwLock::new(Hello::default()),
            lifetimes: RwLock::new(Lifetimes { secret_ms: 60_000, incoming_ms: 600_000 }),
            on_copy: RwLock::new(None),
            on_command: RwLock::new(None),
            on_set: RwLock::new(None),
            on_other: RwLock::new(None),
            on_pair: RwLock::new(None),
            waiting: Mutex::new(HashMap::new()),
            releases: RwLock::new(None),
            entries: RwLock::new(None),
            log,
            closed: AtomicBool::new(false),
        };
        Ok(Arc::new(mesh))
    }

    fn logf(&self, s: &str) {
        (self.log)(s)
    }

    /// This device's own keys.
    pub fn own(&self) -> &Own {
        &self.own
    }

    /// Keeps a keys statement a device brought (a joiner's first) and
    /// passes it on to every peer.
    pub fn take_statement(&self, envelope: &[u8]) -> Result<()> {
        let msgs = {
            let mut st = self.statements.lock().unwrap();
            if !st.add(envelope)? {
                return Ok(());
            }
            st.save()?;
            st.messages()
        };
        for f in msgs {
            self.broadcast(&f, None);
        }
        Ok(())
    }

    /// This device's ID.
    pub fn device(&self) -> DeviceId {
        self.own.device()
    }

    /// The group's state now.
    pub fn state(&self) -> State {
        self.set.lock().unwrap_or_else(std::sync::PoisonError::into_inner).state()
    }

    /// The set, under its lock.
    pub fn set(&self) -> Arc<Mutex<RecordSet>> {
        self.set.clone()
    }

    pub fn on_copy(&self, f: OnCopy) {
        *self.on_copy.write().unwrap() = Some(f);
    }

    pub fn on_command(&self, f: OnCommand) {
        *self.on_command.write().unwrap() = Some(f);
    }

    pub fn on_set(&self, f: OnSet) {
        *self.on_set.write().unwrap() = Some(f);
    }

    pub fn on_other(&self, f: OnOther) {
        *self.on_other.write().unwrap() = Some(f);
    }

    /// Where a pairing on the member port goes while a window is open;
    /// None closes such connections.
    pub fn on_pair(&self, f: Option<OnPair>) {
        *self.on_pair.write().unwrap() = f;
    }

    /// Sends a frame to a connected device: false when it is not connected
    /// or its queue is full.
    pub fn send(&self, to: &DeviceId, frame: Vec<u8>) -> bool {
        self.send_to(to, frame)
    }

    /// Whether a device may be a hub of this one: a device of the group,
    /// not frozen, that holds an admin key or that the root's hubs record
    /// names.
    pub fn may_be_hub(&self, id: &DeviceId) -> bool {
        let st = self.state();
        st.device(id).is_some_and(|d| !d.frozen && (d.admin.is_some() || st.hubs.contains(id)))
    }

    /// What this device's hellos say of it beyond the exchange's fields.
    pub fn set_hello(&self, h: Hello) {
        *self.hello.write().unwrap() = h;
    }

    /// The signed release and entry points this member holds, which its
    /// hellos name and it passes to a peer that holds older ones.
    pub fn with_signed(&self, releases: Arc<Releases>, entries: Arc<Entries>) {
        *self.releases.write().unwrap() = Some(releases);
        *self.entries.write().unwrap() = Some(entries);
    }

    /// The lifetimes copies are judged by.
    pub fn set_lifetimes(&self, l: Lifetimes) {
        *self.lifetimes.write().unwrap() = l;
    }

    /// The last hello of each device connected now.
    pub fn hellos(&self) -> HashMap<DeviceId, Hello> {
        self.hellos.lock().unwrap().clone()
    }

    /// The devices connected now.
    pub fn connected(&self) -> Vec<DeviceId> {
        self.conns.lock().unwrap().keys().copied().collect()
    }

    /// Keeps this device's sealing keys current (`keystore::rotate`); a new
    /// epoch's statement is kept and goes to every peer.
    pub fn rotate(&self) -> Result<()> {
        let group = self.state().group;
        let now = crate::uptime::wall_ms().max(0) as u64;
        let made = keystore::rotate(&mut *self.store.lock().unwrap(), &group, now, Some(now))
            .map_err(|e| e.context("cannot change the sealing key"))?
            .made;
        if let Some(env) = made {
            let msgs = {
                let mut st = self.statements.lock().unwrap();
                st.add(&env)?;
                st.save()?;
                st.messages()
            };
            for f in msgs {
                self.broadcast(&f, None);
            }
        }
        Ok(())
    }

    /// Writes records as this device's root or admin key
    /// (`writers::signer`): f writes them on the set under its lock, then
    /// they are kept and passed on. An error when this device signs none.
    pub fn write<T>(
        &self,
        f: impl FnOnce(&mut RecordSet, &dyn cbb_core::identity::ExternalKey) -> Result<T>,
    ) -> Result<T> {
        let out = {
            let mut set = self.set.lock().unwrap();
            let st = set.state();
            let signer = crate::writers::signer(&self.own, &st)
                .ok_or_else(|| Error::msg("this device holds neither the group's root key nor an admin key"))?;
            f(&mut set, signer)?
        };
        self.changed()?;
        Ok(out)
    }

    /// As write, with a key the caller holds (a phone's admin or root key,
    /// which its app signs with): the records judge whether it may.
    pub fn write_by<T>(
        &self,
        signer: &dyn cbb_core::identity::ExternalKey,
        f: impl FnOnce(&mut RecordSet, &dyn cbb_core::identity::ExternalKey) -> Result<T>,
    ) -> Result<T> {
        let out = {
            let mut set = self.set.lock().unwrap();
            f(&mut set, signer)?
        };
        self.changed()?;
        Ok(out)
    }

    /// Records this device wrote (by its own keys, through the set's
    /// writers): kept and passed on with a hello to every peer.
    pub fn changed(&self) -> Result<()> {
        let set = self.set.lock().unwrap();
        crate::set::save(&self.dir, &set, &self.local)?;
        if let Some(f) = &*self.on_set.read().unwrap() {
            f(&set);
        }
        let hello = self.hello_frame(&set);
        drop(set);
        self.broadcast(&hello, None);
        Ok(())
    }

    fn hello_frame(&self, set: &RecordSet) -> Vec<u8> {
        let mut h = self.hello.read().unwrap().clone();
        let now = crate::uptime::wall_ms();
        if let Some(r) = &*self.releases.read().unwrap() {
            (h.release_keys_seq, h.release_seq) = r.order(now);
        }
        if let Some(e) = &*self.entries.read().unwrap() {
            (h.entries_keys_seq, h.entries_seq) = e.order(now);
        }
        h.wall_ms = now.max(0) as u64;
        link::hello_with(set, h.fields())
    }

    /// On a peer's hello: the release and entry points this member holds,
    /// when the peer's are older.
    fn on_hello(&self, conn: &Conn, h: &Hello) {
        self.hellos.lock().unwrap().insert(conn.peer, h.clone());
        let now = crate::uptime::wall_ms();
        if let Some(r) = &*self.releases.read().unwrap()
            && crate::releases::newer(r.order(now), (h.release_keys_seq, h.release_seq))
            && let Some(f) = r.current(now).and_then(|v| files_frame(m::T_RELEASE, RELEASE_FILES, &v))
        {
            let _ = conn.tx.try_send(f);
        }
        if let Some(e) = &*self.entries.read().unwrap()
            && crate::entries::newer(e.order(now), (h.entries_keys_seq, h.entries_seq))
            && let Some(f) = e.current(now).and_then(|v| files_frame(m::T_ENTRIES, ENTRIES_FILES, &v))
        {
            let _ = conn.tx.try_send(f);
        }
    }

    fn take_signed(&self, conn: &Conn, t: u64, msg: &[u8]) -> Result<()> {
        let now = crate::uptime::wall_ms();
        let (files, what) =
            if t == m::T_RELEASE { (RELEASE_FILES, "release") } else { (ENTRIES_FILES, "entry points") };
        let v = files_value(msg, files).ok_or_else(|| Error::msg(format!("the {what} do not decode")))?;
        let taken = if t == m::T_RELEASE {
            self.releases.read().unwrap().as_ref().map(|r| r.take(&v, now))
        } else {
            self.entries.read().unwrap().as_ref().map(|e| e.take(&v, now))
        };
        match taken {
            Some(Ok(true)) => {
                // Newer here: passed on to the others with a new hello.
                let hello = self.hello_frame(&self.set.lock().unwrap());
                self.broadcast(&hello, Some(&conn.peer));
            }
            Some(Err(e)) => {
                self.logf(&format!("the {what} from {} were not taken: {}", hex(&conn.peer.0[..4]), e.details()))
            }
            Some(Ok(false)) | None => {}
        }
        Ok(())
    }

    fn broadcast(&self, f: &[u8], except: Option<&DeviceId>) {
        let conns: Vec<Arc<Conn>> = self.conns.lock().unwrap().values().cloned().collect();
        for c in conns {
            if Some(&c.peer) != except {
                let _ = c.tx.try_send(f.to_vec());
            }
        }
    }

    fn send_to(&self, id: &DeviceId, f: Vec<u8>) -> bool {
        match self.conns.lock().unwrap().get(id) {
            Some(c) => c.tx.try_send(f).is_ok(),
            None => false,
        }
    }

    /// Seals content to the group's readers and sends it to every peer.
    /// False when the group has no reader for it.
    pub fn copy(&self, content: &Content) -> Result<bool> {
        let state = self.state();
        let now = crate::uptime::wall_ms().max(0) as u64;
        let made = sealed::make(
            &*self.own.member,
            &state,
            &self.statements.lock().unwrap(),
            content,
            self.clock.now(),
            Some(now),
        )?;
        let Some((frame, kept)) = made else { return Ok(false) };
        self.see(&kept.made.id);
        self.kept.lock().unwrap().insert(kept.made.id, kept);
        self.broadcast(&frame, None);
        Ok(true)
    }

    /// Notes a copy's ID: true when it was not seen before.
    fn see(&self, id: &[u8; 16]) -> bool {
        let mut s = self.seen.lock().unwrap();
        if !s.0.insert(*id) {
            return false;
        }
        s.1.push_back(*id);
        while s.1.len() > SEEN_COPIES {
            if let Some(old) = s.1.pop_front() {
                s.0.remove(&old);
            }
        }
        true
    }

    /// Sends a command to device `to`, signed by `signer` (a key this
    /// device holds), and waits for its result.
    pub fn command(
        &self,
        signer: &dyn cbb_core::identity::ExternalKey,
        to: DeviceId,
        kind: u64,
        orders: Option<&[u8]>,
    ) -> Result<CommandResult> {
        let state = self.state();
        let now = crate::uptime::wall_ms().max(0) as u64;
        let f =
            self.book.lock().unwrap().send(signer, &state, &self.statements.lock().unwrap(), to, kind, orders, now)?;
        let id = command_id(&f).ok_or_else(|| Error::msg("the command has no ID"))?;
        let (tx, rx) = mpsc::sync_channel(1);
        self.waiting.lock().unwrap().insert(id, tx);
        if !self.send_to(&to, f) {
            self.waiting.lock().unwrap().remove(&id);
            return Err(Error::msg("the device is not connected"));
        }
        let r = rx.recv_timeout(RESULT_WAIT);
        self.waiting.lock().unwrap().remove(&id);
        r.map_err(|_| Error::msg("the device did not answer the command"))
    }

    /// The TLS configuration this member's server side takes members with.
    pub fn server_config(&self) -> Result<tls::rustls::ServerConfig> {
        bykey::server(&self.own.tls_key()?, self.judge(), cbb_core::alpn::MEMBER, &tls::clock())
    }

    fn client_config(&self, expect: Option<DeviceId>) -> Result<tls::rustls::ClientConfig> {
        let expect = expect.map(|d| cbb_core::format::DeviceId(d.0));
        bykey::client(&self.own.tls_key()?, expect, self.judge(), cbb_core::alpn::MEMBER, &tls::clock())
    }

    fn judge(&self) -> bykey::Judge {
        let set = self.set.clone();
        let own = self.own.hash();
        bykey::by_standing(
            move |p| standing(&set.lock().unwrap_or_else(std::sync::PoisonError::into_inner).state(), &own, p),
            false,
        )
    }

    /// Dials a member at addr (the device `expect`, when known) and runs
    /// the connection until it ends: the device it was with.
    pub fn dial(self: &Arc<Self>, addr: SocketAddr, expect: Option<DeviceId>) -> Result<DeviceId> {
        let sock = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| Error::with(format!("cannot reach {addr}"), e))?;
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(|e| Error::with("cannot set the timeout", e))?;
        let mut s = tls::Session::client(Arc::new(self.client_config(expect)?), bykey::unsent_name())?;
        tls::handshake(&mut s, &sock, "the handshake failed")?;
        self.run(sock, s, true)
    }

    /// Takes a connection a member made and runs it until it ends: the
    /// device it was with.
    pub fn accept(self: &Arc<Self>, sock: TcpStream) -> Result<DeviceId> {
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(|e| Error::with("cannot set the timeout", e))?;
        let mut s = tls::Session::server(Arc::new(self.server_config()?))?;
        tls::handshake(&mut s, &sock, "the handshake failed")?;
        self.run(sock, s, false)
    }

    /// Takes a connection on the member port, where members connect
    /// (`cbb/4`) and a device that joins pairs (`cbb-pair/3`): a member by
    /// its standing in the records, a pairing to the open window. The
    /// device a member connection was with; None for a pairing.
    pub fn accept_port(self: &Arc<Self>, sock: TcpStream) -> Result<Option<DeviceId>> {
        self.accept_port_with(sock, &mut || {})
    }

    /// As `accept_port`; handshaken is called once the handshake is over,
    /// whether it worked or not.
    pub fn accept_port_with(
        self: &Arc<Self>,
        sock: TcpStream,
        handshaken: &mut dyn FnMut(),
    ) -> Result<Option<DeviceId>> {
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(|e| Error::with("cannot set the timeout", e))?;
        let mut cfg = bykey::server(&self.own.tls_key()?, bykey::any_key(), cbb_core::alpn::MEMBER, &tls::clock())?;
        cfg.alpn_protocols = vec![cbb_core::alpn::MEMBER.to_vec(), cbb_core::alpn::PAIR.to_vec()];
        let (cfg, exporter) = bykey::exporting_server(cfg);
        let mut s = tls::Session::server(Arc::new(cfg))?;
        let shook = tls::handshake(&mut s, &sock, "the handshake failed");
        handshaken();
        shook?;
        if cbb_core::alpn::is_pair(s.alpn_protocol()) {
            let x = bykey::pairing_exporter(&s, &exporter)?;
            return match &*self.on_pair.read().unwrap() {
                Some(f) => {
                    f(sock, s, x);
                    Ok(None)
                }
                None => Err(Error::msg("a device asked to pair, but no pairing window is open")),
            };
        }
        let point = bykey::peer_key(s.peer_certificates()).ok_or_else(|| Error::msg("the peer showed no key"))?;
        (self.judge())(&point).map_err(|why| Error::msg(format!("the peer was refused: {why}")))?;
        self.run(sock, s, false).map(Some)
    }

    /// Runs a member connection until it ends; dialed says this device
    /// dialed it. A new connection to a peer replaces the old one, as a
    /// reconnect does, unless the old one was dialed by the device with the
    /// lower ID and this one was not: when both dial at once, the two keep
    /// the same connection, and neither is left without one.
    fn run(self: &Arc<Self>, sock: TcpStream, session: tls::Session, dialed: bool) -> Result<DeviceId> {
        let point = bykey::peer_key(session.peer_certificates()).ok_or_else(|| Error::msg("the peer showed no key"))?;
        let peer_key = Key::es256(point.to_vec());
        let peer = peer_key.device_id();
        let lower_dialed = dialed == (self.device().0 < peer.0);
        sock.set_read_timeout(Some(TIMEOUT)).map_err(|e| Error::with("cannot set the timeout", e))?;
        // A peer that stops reading ends the connection rather than holding
        // the writer, and the TLS lock with it, for ever.
        sock.set_write_timeout(Some(TIMEOUT)).map_err(|e| Error::with("cannot set the timeout", e))?;
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(QUEUE_LEN);
        let w = sock.try_clone().map_err(|e| Error::with("cannot use the connection", e))?;
        let conn = Arc::new(Conn {
            peer,
            tls: Mutex::new(session),
            sock: w,
            tx,
            closed: AtomicBool::new(false),
            lower_dialed,
        });
        {
            let mut conns = self.conns.lock().unwrap();
            if let Some(old) = conns.get(&peer)
                && old.lower_dialed
                && !lower_dialed
                && !old.closed.load(Ordering::SeqCst)
            {
                conn.close();
                return Ok(peer);
            }
            if let Some(old) = conns.insert(peer, conn.clone()) {
                old.close();
            }
        }
        let writer = {
            let conn = conn.clone();
            std::thread::spawn(move || {
                loop {
                    match rx.recv_timeout(PING_EVERY) {
                        Ok(f) => {
                            if conn.write(&f).is_err() {
                                break;
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            if conn.closed.load(Ordering::SeqCst) || conn.write(&ping()).is_err() {
                                break;
                            }
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                conn.close();
            })
        };
        // The hello, then every statement held.
        {
            let set = self.set.lock().unwrap();
            let _ = conn.tx.try_send(self.hello_frame(&set));
        }
        for f in self.statements.lock().unwrap().messages() {
            let _ = conn.tx.try_send(f);
        }
        let mut x = Exchange::new(self.own.hash(), point);
        let mut reader = Reader { c: &conn, buf: Vec::new() };
        let end = loop {
            let msg = match media::read_any(&mut reader) {
                Ok(media::In::Msg(m)) => m,
                Ok(media::In::Chunk(c)) => {
                    self.take_chunk(c);
                    continue;
                }
                Err(e) => break e,
            };
            if let Err(e) = self.take(&conn, &mut x, &msg) {
                break e;
            }
        };
        {
            let mut conns = self.conns.lock().unwrap();
            if conns.get(&peer).is_some_and(|c| Arc::ptr_eq(c, &conn)) {
                conns.remove(&peer);
                self.hellos.lock().unwrap().remove(&peer);
            }
        }
        conn.close();
        drop(conn);
        let _ = writer.join();
        self.logf(&format!("the connection with {} ended: {}", hex(&peer.0[..4]), end.details()));
        Ok(peer)
    }

    fn take(&self, conn: &Conn, x: &mut Exchange, msg: &[u8]) -> Result<()> {
        let out = {
            let mut set = self.set.lock().unwrap();
            let out = x.take(&mut set, msg)?;
            if out.changed {
                crate::set::save(&self.dir, &set, &self.local)?;
                self.statements.lock().unwrap().prune(&set.state());
                if let Some(f) = &*self.on_set.read().unwrap() {
                    f(&set);
                }
            }
            out
        };
        if let Some((theirs, ours)) = out.stuck {
            self.logf(&format!(
                "the records' exchange passed its rounds: the peer's digest {}, ours {}",
                hex(&theirs),
                hex(&ours)
            ));
        }
        for f in out.send {
            let _ = conn.tx.try_send(f);
        }
        if out.changed {
            let hello = self.hello_frame(&self.set.lock().unwrap());
            self.broadcast(&hello, None);
        }
        match out.other {
            None => {
                if let Ok((m::T_HELLO, v, _)) = cbb_core::msg::read_noted(msg) {
                    self.on_hello(conn, &Hello::read(&v));
                }
                Ok(())
            }
            Some(m::T_PING) => Ok(()),
            Some(t @ (m::T_RELEASE | m::T_ENTRIES)) => self.take_signed(conn, t, msg),
            Some(m::T_BYE) => Err(Error::msg("the peer said goodbye")),
            Some(cbb_core::msg::wave4::T_KEYS) => self.take_keys(conn, msg),
            Some(copies::T_COPY) => self.take_copy(conn, msg),
            Some(cbb_core::commands::T_COMMAND) => self.take_command(conn, msg),
            Some(cbb_core::msg::tables::T_RESULT) => {
                self.take_result(msg);
                Ok(())
            }
            Some(copies::T_RESEAL) => self.take_reseal(conn, msg),
            Some(m::T_GET) => self.take_get(conn, msg),
            Some(m::T_MISSING) => {
                self.take_missing(msg);
                Ok(())
            }
            // A tunnel offer or a hub share only from a device that may be
            // a hub, by the records, not by what its hello claims.
            Some(t @ (cbb_core::msg::tables::T_TUNNEL | cbb_core::msg::tables::T_HUBS))
                if !self.may_be_hub(&conn.peer) =>
            {
                self.logf(&format!(
                    "ignored message {t} from {}: it may not be a hub of the group",
                    hex(&conn.peer.0[..4])
                ));
                Ok(())
            }
            Some(
                t @ (cbb_core::msg::tables::T_CREDENTIALS
                | cbb_core::msg::tables::T_TUNNEL
                | cbb_core::msg::tables::T_HUBS
                | cbb_core::msg::tables::T_GUEST
                | m::T_REACH
                | m::T_EVIDENCE
                | cbb_core::msg::tables::T_WAITING
                | cbb_core::msg::tables::T_DISMISS),
            ) => {
                if let Some(f) = &*self.on_other.read().unwrap() {
                    f(&conn.peer, t, msg);
                }
                Ok(())
            }
            // A message of a later version, or one a member does not take.
            Some(_) => Ok(()),
        }
    }

    fn take_keys(&self, conn: &Conn, msg: &[u8]) -> Result<()> {
        let new = {
            let mut st = self.statements.lock().unwrap();
            let n = st.take_message(msg)?;
            if n > 0 {
                st.save()?;
            }
            n
        };
        if new > 0 {
            // Passed on to the others, as every member does.
            let f = frame::write(&cbb_core::format::cbor::decode(msg).map_err(|r| Error::msg(r.to_string()))?);
            self.broadcast(&f, Some(&conn.peer));
        }
        Ok(())
    }

    fn take_copy(&self, conn: &Conn, msg: &[u8]) -> Result<()> {
        let state = self.state();
        let now = crate::uptime::wall_ms().max(0) as u64;
        let taken = {
            let store = self.store.lock().unwrap();
            let mut marks = self.marks.lock().unwrap();
            sealed::take(msg, &self.device(), &state, &*store, &mut marks, *self.lifetimes.read().unwrap(), Some(now))
        };
        let taken = match taken {
            Ok(t) => t,
            Err(e) => {
                self.logf(&format!("a copy from {} was not taken: {}", hex(&conn.peer.0[..4]), e.details()));
                return Ok(());
            }
        };
        // The copy checked: passed on once to every other peer.
        if let Some(id) = copy_id(msg)
            && self.see(&id)
        {
            let f = frame::write(&cbb_core::format::cbor::decode(msg).map_err(|r| Error::msg(r.to_string()))?);
            self.broadcast(&f, Some(&conn.peer));
        }
        match taken {
            Taken::New { id, content, origin, signed, age_ms, blob } => {
                {
                    let mut marks = self.marks.lock().unwrap();
                    marks.wrote(&origin, signed);
                    let _ = crate::files::write_atomic(&self.dir.join(MARKS_FILE), &marks.encode(), 0o600);
                }
                if let Some(f) = &*self.on_copy.read().unwrap() {
                    f(&Arrived { id, content: *content, origin, age_ms, blob, from: conn.peer });
                }
            }
            Taken::Reseal(f) => {
                let _ = conn.tx.try_send(f);
            }
            Taken::Old(_) | Taken::PassedOn | Taken::Dropped => {}
        }
        Ok(())
    }

    fn take_reseal(&self, conn: &Conn, msg: &[u8]) -> Result<()> {
        let (_, v, _) = cbb_core::msg::read_noted(msg).map_err(|r| Error::msg(format!("reseal breaks {r}")))?;
        let Some(id) = v.get(2).and_then(Value::as_bytes).and_then(|b| <[u8; 16]>::try_from(b).ok()) else {
            return Ok(());
        };
        let Some(kept) = self.kept.lock().unwrap().get(&id).cloned() else { return Ok(()) };
        // Sealed again to the asker's current statement only, when it was
        // a reader and still reads.
        let state = self.state();
        let sealing = self.statements.lock().unwrap().sealing(&state);
        let readers = copies::readers(&state, &sealing, &kept.content, &self.device(), &[], None);
        let Some(r) = readers.into_iter().find(|r| r.id == conn.peer) else { return Ok(()) };
        // A copy with a blob keeps its copy key, so that its blob opens.
        let copy = match &kept.k {
            Some(k) => copies::seal_keyed(&*self.own.member, &[r], &kept.made, &kept.content, k),
            None => copies::seal(&*self.own.member, &[r], &kept.made, &kept.content),
        }
        .map_err(|e| e.context("cannot seal the copy again"))?;
        let f = copies::message(&copy).map_err(|r| Error::msg(format!("the copy breaks {r}")))?;
        let _ = conn.tx.try_send(f);
        Ok(())
    }

    fn take_command(&self, conn: &Conn, msg: &[u8]) -> Result<()> {
        let (state, keys) = {
            let set = self.set.lock().unwrap();
            (set.state(), Keys::of(&set))
        };
        let now = crate::uptime::wall_ms().max(0) as u64;
        let taken = {
            let store = self.store.lock().unwrap();
            self.book.lock().unwrap().take(msg, self.device(), &state, &keys, &*store, Some(now))
        };
        match taken {
            Ok(t) => {
                let r = match &*self.on_command.read().unwrap() {
                    Some(f) => f(&t),
                    None => Err(Error::msg("this device carries out no command")),
                };
                let f = match r {
                    Ok(()) => result_frame(&t.id, &self.device(), 1, ""),
                    Err(e) => result_frame(&t.id, &self.device(), 3, &e.to_string()),
                };
                let _ = conn.tx.try_send(f);
            }
            Err(r) => {
                if let Some(e) = &r.fault {
                    self.logf(&format!("a command was not kept: {}", e.details()));
                }
                if let Some(f) = r.answer {
                    let _ = conn.tx.try_send(f);
                }
            }
        }
        Ok(())
    }

    fn take_result(&self, msg: &[u8]) {
        let Ok((_, v, _)) = cbb_core::msg::read_noted(msg) else { return };
        let Some(id) = v.get(2).and_then(Value::as_bytes).and_then(|b| <[u8; 16]>::try_from(b).ok()) else { return };
        let by = v.get(3).and_then(Value::as_bytes).and_then(DeviceId::from_slice).unwrap_or_default();
        let r = CommandResult {
            by,
            status: v.get(4).and_then(Value::as_uint).unwrap_or(0),
            reason: v.get(5).and_then(Value::as_text).unwrap_or_default().to_string(),
        };
        if let Some(tx) = self.waiting.lock().unwrap().remove(&id) {
            let _ = tx.try_send(r);
        }
    }

    /// Where a peer stands in the group now.
    pub fn standing_of(&self, point: &[u8; 65]) -> Standing {
        standing(&self.state(), &self.own.hash(), point)
    }

    /// Closes every connection, and takes no more.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.close_connections();
    }

    /// Ends every connection with a goodbye; new ones are still taken.
    pub fn close_connections(&self) {
        for c in self.conns.lock().unwrap().values() {
            let bye = frame::write(&Value::Map(vec![(frame::FIELD_T, Value::Uint(m::T_BYE))]));
            let _ = c.write(&bye);
            c.close();
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// The release's files and their fields in message `release`.
const RELEASE_FILES: &[(&str, u16)] = &[("keys", 2), ("channel", 3), ("release", 4)];
/// The entry points' files and their fields in message `entries`.
const ENTRIES_FILES: &[(&str, u16)] = &[("keys", 2), ("entries", 3)];

/// Message `release` or `entries` from the files held, `{name: file}`:
/// each file's bytes as published.
fn files_frame(t: u64, files: &[(&str, u16)], v: &RawValue) -> Option<Vec<u8>> {
    let map: HashMap<&str, &RawValue> = serde_json::from_str(v.get()).ok()?;
    let mut f = vec![(frame::FIELD_T, Value::Uint(t))];
    for (name, n) in files {
        f.push((*n, Value::Bytes(map.get(name)?.get().as_bytes())));
    }
    Some(frame::write(&Value::Map(f)))
}

/// The files of message `release` or `entries` (its body) as `{name: file}`,
/// each file's bytes kept as they came.
fn files_value(msg: &[u8], files: &[(&str, u16)]) -> Option<Box<RawValue>> {
    let (_, v, _) = cbb_core::msg::read_noted(msg).ok()?;
    let mut out = String::from("{");
    for (i, (name, n)) in files.iter().enumerate() {
        let file = RawValue::from_string(String::from_utf8(v.get(*n)?.as_bytes()?.to_vec()).ok()?).ok()?;
        if i > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(name).ok()?);
        out.push(':');
        out.push_str(file.get());
    }
    out.push('}');
    RawValue::from_string(out).ok()
}

/// A command's ID from its message frame.
fn command_id(f: &[u8]) -> Option<[u8; 16]> {
    let (_, v, _) = cbb_core::msg::read_noted(f.get(4..)?).ok()?;
    let env = v.get(2)?.encode();
    cbb_core::commands::Command::read(&env).ok().map(|c| c.id)
}

/// A copy's ID from message `copy` (its body), as its header names it.
fn copy_id(msg: &[u8]) -> Option<[u8; 16]> {
    let (_, v, _) = cbb_core::msg::read_noted(msg).ok()?;
    let c = cbb_core::format::copy::Copy::from_value(v.get(2)?).ok()?;
    c.header.get(1).and_then(Value::as_bytes).and_then(|b| b.try_into().ok())
}

mod media;

#[cfg(test)]
pub(crate) mod tests;
