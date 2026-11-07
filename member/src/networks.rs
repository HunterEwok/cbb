// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The networks where this device met its group, as Go's networks.go and
//! internal/netid (docs/design.md, "Known networks"): it was created or
//! joined there, opened a pairing window there, or a member connection
//! came up there. Only on those does it publish itself by mDNS and take
//! connections on the member port; elsewhere, in a café or a hotel, it only
//! browses, so that its device ID and group tag do not follow it around.
//! networks.json keeps a random key and the networks' IDs under it, in Go's
//! format, so a computer moving from the Go service keeps its list.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cbb_core::certs::b64;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// The file in the state directory.
pub const FILE: &str = "networks.json";
/// The networks it keeps at most, the least recently seen going first.
const MAX: usize = 64;
/// How long the interfaces' list is trusted before it is read again.
const LIST_EVERY: Duration = Duration::from_secs(2);
/// How long the first look at the interfaces waits for their list.
const FIRST_LIST: Duration = Duration::from_secs(2);
/// How long the gateways' addresses are trusted before they are read again.
const GATEWAYS_EVERY: Duration = Duration::from_secs(30);

/// An interface that is up, with the addresses mDNS may publish.
#[derive(Clone, Debug)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub prefixes: Vec<(IpAddr, u8)>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Known {
    /// The ID of the network's addresses alone, which tells it while its
    /// gateway's address is not known yet.
    net: String,
    /// When it was seen last, in Unix seconds.
    seen: i64,
}

#[derive(Serialize, Deserialize, Default)]
struct File {
    #[serde(with = "b64", default)]
    key: Vec<u8>,
    #[serde(default)]
    known: BTreeMap<String, Known>,
}

struct Inner {
    file: File,
    gw: Option<(HashMap<u32, String>, Instant)>,
}

/// The known networks.
pub struct Networks {
    path: PathBuf,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    inner: Mutex<Inner>,
    /// Lists the interfaces and reads the gateways; tests replace them.
    interfaces: Arc<dyn Fn() -> Vec<Interface> + Send + Sync>,
    gateways: Box<dyn Fn() -> HashMap<u32, String> + Send + Sync>,
    /// The interfaces as a thread listed them last, and when: a connection
    /// or a status never waits for the system's list, which can hang (as
    /// musl's getifaddrs under qemu-mips does).
    listed: Arc<Mutex<Listed>>,
}

#[derive(Default)]
struct Listed {
    ifs: Vec<Interface>,
    at: Option<Instant>,
    listing: bool,
    /// The first list was waited for once already.
    waited: bool,
}

impl Networks {
    /// Reads the known networks from dir, as Go's loadNetworks: without the
    /// file, a device already in a group (in_group) takes the networks it is
    /// on now as known, as it is most likely at home when it is updated to a
    /// version that keeps the list.
    pub fn load(dir: &std::path::Path, in_group: bool, log: Arc<dyn Fn(&str) + Send + Sync>) -> Arc<Networks> {
        Self::load_with(dir, in_group, log, Arc::new(system_interfaces), Box::new(gateways))
    }

    fn load_with(
        dir: &std::path::Path,
        in_group: bool,
        log: Arc<dyn Fn(&str) + Send + Sync>,
        interfaces: Arc<dyn Fn() -> Vec<Interface> + Send + Sync>,
        gateways: Box<dyn Fn() -> HashMap<u32, String> + Send + Sync>,
    ) -> Arc<Networks> {
        let path = dir.join(FILE);
        let n = Networks {
            path: path.clone(),
            log,
            inner: Mutex::new(Inner { file: File::default(), gw: None }),
            interfaces,
            gateways,
            listed: Arc::new(Mutex::new(Listed::default())),
        };
        let n = Arc::new(n);
        // Learnt in the background: the start does not wait for the list.
        let learn_all = |n: &Arc<Networks>| {
            let n = n.clone();
            std::thread::spawn(move || n.learn_all());
        };
        match std::fs::read(&path) {
            Ok(b) => match serde_json::from_slice::<File>(&b) {
                Ok(f) if f.key.len() >= 16 => n.inner.lock().unwrap().file = f,
                _ => {
                    (n.log)(&format!(
                        "cbb: {FILE} cannot be read; this device takes the networks it is on now as known"
                    ));
                    learn_all(&n);
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if in_group {
                    learn_all(&n);
                }
            }
            Err(e) => (n.log)(&format!("cbb: reading {FILE}: {e}")),
        }
        n
    }

    /// Whether the local address a of a connection is on a known network.
    /// An address of no interface (the tunnel's, in the process) is not.
    pub fn knows(&self, a: IpAddr) -> bool {
        let Some(f) = self.find(a) else { return false };
        self.known(&mut self.inner.lock().unwrap(), &f)
    }

    /// Makes the network of the local address a known, as a member
    /// connection came up there; whether it is new.
    pub fn learn(&self, a: IpAddr) -> bool {
        match self.find(a) {
            Some(f) => self.add(&[f]),
            None => false,
        }
    }

    /// Makes the networks of every interface known: this device made or
    /// joined its group, or opens a pairing window, here; whether one is new.
    pub fn learn_all(&self) -> bool {
        self.add(&self.ifs())
    }

    /// The interfaces on known networks, where mDNS publishes this device.
    pub fn published(&self) -> Vec<Interface> {
        let mut inner = self.inner.lock().unwrap();
        self.ifs().into_iter().filter(|f| self.known(&mut inner, f)).collect()
    }

    /// The interfaces on networks this device does not know, for status.
    pub fn unknown(&self) -> Vec<String> {
        let mut inner = self.inner.lock().unwrap();
        let mut out: Vec<String> = self
            .ifs()
            .into_iter()
            .filter(|f| !self.ids(&mut inner, f).0.is_empty() && !self.known(&mut inner, f))
            .map(|f| f.name)
            .collect();
        out.sort();
        out
    }

    /// The interfaces as listed last; a thread lists them again when the
    /// list is older than LIST_EVERY.
    fn ifs(&self) -> Vec<Interface> {
        let mut l = self.listed.lock().unwrap();
        if !l.listing && l.at.is_none_or(|at| at.elapsed() >= LIST_EVERY) {
            l.listing = true;
            let (list, listed) = (self.interfaces.clone(), self.listed.clone());
            std::thread::spawn(move || {
                let ifs = list();
                let mut l = listed.lock().unwrap();
                (l.ifs, l.at, l.listing) = (ifs, Some(Instant::now()), false);
            });
        }
        if l.at.is_some() || l.waited {
            return l.ifs.clone();
        }
        // The first list, waited for a moment, once.
        l.waited = true;
        drop(l);
        let until = Instant::now() + FIRST_LIST;
        loop {
            let l = self.listed.lock().unwrap();
            if l.at.is_some() || Instant::now() > until {
                return l.ifs.clone();
            }
            drop(l);
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn find(&self, a: IpAddr) -> Option<Interface> {
        let a = unmapped(a);
        self.ifs().into_iter().find(|f| f.prefixes.iter().any(|(p, _)| *p == a))
    }

    /// The IDs of an interface's network, with its gateway and without; ""
    /// when it has none.
    fn ids(&self, inner: &mut Inner, f: &Interface) -> (String, String) {
        if inner.file.key.is_empty() {
            inner.file.key = random_key();
        }
        if inner.gw.as_ref().is_none_or(|(_, at)| at.elapsed() > GATEWAYS_EVERY) {
            inner.gw = Some(((self.gateways)(), Instant::now()));
        }
        let gw = inner.gw.as_ref().and_then(|(m, _)| m.get(&f.index)).cloned().unwrap_or_default();
        (id(&inner.file.key, &f.prefixes, &gw), id(&inner.file.key, &f.prefixes, ""))
    }

    /// Whether an interface's network is known: by its gateway's address
    /// and its addresses, or, while the gateway's address is not known yet,
    /// by its addresses alone.
    fn known(&self, inner: &mut Inner, f: &Interface) -> bool {
        let (full, addrs) = self.ids(inner, f);
        if full.is_empty() {
            return false;
        }
        if inner.file.known.contains_key(&full) {
            return true;
        }
        let no_gw = inner.gw.as_ref().is_none_or(|(m, _)| !m.contains_key(&f.index));
        if no_gw {
            return inner.file.known.values().any(|k| k.net == addrs);
        }
        // A network learned before its gateway's address was known is bound
        // to the first gateway seen on it.
        if let Some(k) = inner.file.known.remove(&addrs) {
            inner.file.known.insert(full, k);
            self.save(inner);
            return true;
        }
        false
    }

    fn add(&self, ifs: &[Interface]) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        let mut added = false;
        for f in ifs {
            let (full, addrs) = self.ids(&mut inner, f);
            if full.is_empty() {
                continue;
            }
            added |= !inner.file.known.contains_key(&full);
            inner.file.known.insert(full, Known { net: addrs, seen: now });
        }
        while inner.file.known.len() > MAX {
            let oldest = inner.file.known.iter().min_by_key(|(_, k)| k.seen).map(|(id, _)| id.clone());
            if let Some(id) = oldest {
                inner.file.known.remove(&id);
            }
        }
        if added {
            self.save(&inner);
        }
        added
    }

    fn save(&self, inner: &Inner) {
        let res = serde_json::to_vec(&inner.file)
            .map_err(|e| e.to_string())
            .and_then(|b| crate::files::write_atomic(&self.path, &b, 0o600).map_err(|e| e.message().to_string()));
        if let Err(e) = res {
            (self.log)(&format!("cbb: saving the known networks: {e}"));
        }
    }
}

fn random_key() -> Vec<u8> {
    let mut k = vec![0u8; 32];
    let _ = getrandom::fill(&mut k);
    k
}

fn unmapped(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(a, IpAddr::V4),
        a => a,
    }
}

/// Whether mDNS may publish the address a, as Go's mdns.Published: private
/// IPv4, unique-local and link-local IPv6.
pub fn published_addr(a: IpAddr) -> bool {
    match unmapped(a) {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// A network's identity, as Go's netid.ID: an HMAC under key of the
/// interface's IPv4 networks (its IPv6 networks when it has none, as ISPs
/// change IPv6 prefixes) and gw, the link-layer address of its gateway or
/// "", so that the list says nothing about the networks.
pub fn id(key: &[u8], prefixes: &[(IpAddr, u8)], gw: &str) -> String {
    let (mut four, mut six) = (Vec::new(), Vec::new());
    for (a, bits) in prefixes {
        match unmapped(*a) {
            IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_link_local() && *bits <= 32 => {
                let m = if *bits == 0 { 0 } else { u32::MAX << (32 - u32::from(*bits)) };
                four.push(format!("{}/{bits}", std::net::Ipv4Addr::from(u32::from(v4) & m)));
            }
            IpAddr::V6(v6) if !v6.is_loopback() && (v6.segments()[0] & 0xffc0) != 0xfe80 && *bits <= 128 => {
                let m = if *bits == 0 { 0 } else { u128::MAX << (128 - u32::from(*bits)) };
                six.push(format!("{}/{bits}", std::net::Ipv6Addr::from(u128::from(v6) & m)));
            }
            _ => {}
        }
    }
    let mut nets = if four.is_empty() { six } else { four };
    if nets.is_empty() {
        return String::new();
    }
    nets.sort();
    nets.dedup();
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key");
    for n in &nets {
        m.update(n.as_bytes());
        m.update(&[0]);
    }
    m.update(gw.as_bytes());
    m.finalize().into_bytes()[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// The interfaces that are up, with the addresses mDNS may publish, within
/// the interface list (CBB_INTERFACES), as Go's systemInterfaces.
fn system_interfaces() -> Vec<Interface> {
    let mut out: Vec<Interface> = Vec::new();
    for i in if_addrs::get_if_addrs().unwrap_or_default() {
        if i.is_loopback() || !crate::interfaces::allowed(&i.name) || !published_addr(i.ip()) {
            continue;
        }
        let bits = match &i.addr {
            if_addrs::IfAddr::V4(a) => a.prefixlen,
            if_addrs::IfAddr::V6(a) => a.prefixlen,
        };
        let p = (unmapped(i.ip()), bits);
        match out.iter_mut().find(|f| f.name == i.name) {
            Some(f) => f.prefixes.push(p),
            None => out.push(Interface { index: i.index.unwrap_or(0), name: i.name, prefixes: vec![p] }),
        }
    }
    out
}

/// The link-layer address of each interface's IPv4 default gateway, by
/// index, as Go's netid.Gateways: from /proc/net/route and /proc/net/arp on
/// Linux, none elsewhere.
fn gateways() -> HashMap<u32, String> {
    let (Ok(routes), Ok(arp)) = (std::fs::read_to_string("/proc/net/route"), std::fs::read_to_string("/proc/net/arp"))
    else {
        return HashMap::new();
    };
    gateways_from(&routes, &arp, &|name| {
        let c = std::ffi::CString::new(name).ok()?;
        // SAFETY: c is a valid C string for the call.
        let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
        (i != 0).then_some(i)
    })
}

fn gateways_from(routes: &str, arp: &str, index: &dyn Fn(&str) -> Option<u32>) -> HashMap<u32, String> {
    let mut gw: HashMap<&str, std::net::Ipv4Addr> = HashMap::new();
    for l in routes.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 4 || f[1] != "00000000" {
            continue;
        }
        let Ok(flags) = u32::from_str_radix(f[3], 16) else { continue };
        let Ok(raw) = u32::from_str_radix(f[2], 16) else { continue };
        if flags & 0x2 == 0 {
            continue; // RTF_GATEWAY
        }
        gw.entry(f[0]).or_insert(std::net::Ipv4Addr::from(raw.swap_bytes()));
    }
    let mut out = HashMap::new();
    for l in arp.lines().skip(1) {
        // IP address, HW type, Flags, HW address, Mask, Device
        let r: Vec<&str> = l.split_whitespace().collect();
        if r.len() < 6 || r[2] == "0x0" {
            continue;
        }
        let Ok(ip) = r[0].parse::<std::net::Ipv4Addr>() else { continue };
        if gw.get(r[5]) != Some(&ip) {
            continue;
        }
        let mac: Vec<&str> = r[3].split(':').collect();
        if mac.len() != 6 || mac.iter().any(|b| b.len() != 2 || u8::from_str_radix(b, 16).is_err()) {
            continue;
        }
        if let Some(i) = index(r[5]) {
            out.insert(i, r[3].to_ascii_lowercase());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> (IpAddr, u8) {
        let (a, b) = s.split_once('/').unwrap();
        (a.parse().unwrap(), b.parse().unwrap())
    }

    #[test]
    fn ids_as_go() {
        // The values Go's netid.ID gives for the same networks
        // (testdata/interop/go-netid.json, written by Go's TestIDVectors).
        #[derive(Deserialize)]
        struct Case {
            prefixes: Vec<String>,
            gateway: String,
            id: String,
        }
        #[derive(Deserialize)]
        struct Vectors {
            #[serde(with = "crate::certs::b64")]
            key: Vec<u8>,
            cases: Vec<Case>,
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/go-netid.json");
        let v: Vectors = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(v.cases.len(), 6);
        for c in &v.cases {
            let nets: Vec<(IpAddr, u8)> = c.prefixes.iter().map(|s| p(s)).collect();
            assert_eq!(id(&v.key, &nets, &c.gateway), c.id, "{:?} {:?}", c.prefixes, c.gateway);
        }
        // Another address and IPv6 prefix on the same network: the same;
        // another gateway: another; a link-local address alone: none.
        assert_eq!(v.cases[3].id, v.cases[0].id);
        assert_ne!(v.cases[4].id, v.cases[0].id);
        assert_eq!(v.cases[5].id, "");
    }

    #[test]
    fn reads_go_s_file() {
        // As Go's networksJSON marshals it: the key in standard base64.
        let go = br#"{"key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","known":{"82db5862fba2668b8d635ea4987a438b":{"net":"2adcec70816d94a395dfd553b451a30d","seen":1794000000}}}"#;
        let f: File = serde_json::from_slice(go).unwrap();
        assert_eq!(f.key, (0u8..32).collect::<Vec<_>>());
        assert_eq!(f.known["82db5862fba2668b8d635ea4987a438b"].net, "2adcec70816d94a395dfd553b451a30d");
        assert_eq!(serde_json::to_vec(&f).unwrap(), go.to_vec());
    }

    #[test]
    fn gateways_from_proc() {
        let routes = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\nwlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\nwlan0\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n";
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n192.168.0.1      0x1         0x2         AA:bb:cc:dd:ee:ff     *        wlan0\n192.168.0.7      0x1         0x2         11:22:33:44:55:66     *        wlan0\n";
        let m = gateways_from(routes, arp, &|n| (n == "wlan0").then_some(3));
        assert_eq!(m.get(&3).map(String::as_str), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn learns_and_binds_the_gateway() {
        let dir = std::env::temp_dir().join(format!("cbb-networks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let home = Interface { index: 2, name: "eth0".into(), prefixes: vec![p("192.168.0.5/24")] };
        let ifs = Arc::new(Mutex::new(vec![home.clone()]));
        let gws = Arc::new(Mutex::new(HashMap::new()));
        let make = || {
            let (i, g) = (ifs.clone(), gws.clone());
            Networks::load_with(
                &dir,
                false,
                Arc::new(|_: &str| {}),
                Arc::new(move || i.lock().unwrap().clone()),
                Box::new(move || g.lock().unwrap().clone()),
            )
        };
        let n = make();
        let at: IpAddr = "192.168.0.5".parse().unwrap();
        assert!(!n.knows(at), "a network is known before it is learnt");
        assert_eq!(n.unknown(), vec!["eth0".to_string()]);
        // Learnt before its gateway's address is known, then bound to it.
        assert!(n.learn(at));
        assert!(!n.learn(at));
        assert!(n.knows(at));
        gws.lock().unwrap().insert(2, "aa:bb:cc:dd:ee:ff".to_string());
        let n = make();
        assert!(n.knows(at), "the network learnt without its gateway");
        // The same subnet behind another gateway is another network.
        gws.lock().unwrap().insert(2, "11:22:33:44:55:66".to_string());
        let n = make();
        assert!(!n.knows(at));
        assert!(n.published().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
