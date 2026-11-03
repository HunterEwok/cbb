// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// A connection that can be closed, which makes a blocked read or write
/// fail: a TLS connection in the app, a socket in tests.
public protocol ClosableTransport: FrameTransport {
    func close()
    /// The peer's leaf certificate from the TLS handshake, DER; nil when
    /// there is none.
    var peerCertificate: Data? { get }
}

extension ClosableTransport {
    public var peerCertificate: Data? { nil }
    public var peerChain: [Data] { peerCertificate.map { [$0] } ?? [] }
}

/// Keeps the group's signed records for a node (docs/protocol.md, section
/// 10). Its methods are called from the node's actor.
public protocol RecordStore: AnyObject, Sendable {
    /// The digest a hello carries; nil without records.
    var digest: String? { get }
    /// Every record, for a peer whose digest differs.
    var all: [Member.Record] { get }
    /// Takes records a peer sent and returns those that were new and valid.
    func add(_ records: [Member.Record]) -> [Member.Record]
    /// Why the records refuse a peer's certificate chain (leaf first), as
    /// RecordSet.refused, or nil: a removed device is dropped by its key,
    /// not only by its ID.
    func refused(chain: [Data]) -> String?
    /// Whether the peer with this verified chain may be the group's hub, as
    /// RecordSet.mayHost.
    func mayHost(_ device: String, chain: [Data]) -> Bool
    /// Whether the state stops the exchange with the peer of this chain, as
    /// RecordSet.stopped: its connection carries records only.
    func stopped(chain: [Data]) -> Bool
    /// Whether this member sends the device no secret, as
    /// RecordSet.noSecrets.
    func noSecrets(to device: String?) -> Bool
}

/// Keeps the group's server credentials for a node (docs/protocol.md,
/// section 18), which it sends each peer after the hello and passes on.
public protocol CredentialKeeper: AnyObject, Sendable {
    /// Every credential kept.
    var all: [ServerCredentials.Credential] { get }
    /// Takes credentials a peer sent and returns those that were new and
    /// valid.
    func add(_ credentials: [ServerCredentials.Credential]) -> [ServerCredentials.Credential]
}

public extension RecordStore {
    func refused(chain: [Data]) -> String? { nil }
    func mayHost(_ device: String, chain: [Data]) -> Bool { true }
    func stopped(chain: [Data]) -> Bool { false }
    func noSecrets(to device: String?) -> Bool { false }
}

/// The phone as a member: its sync engine and its connections to the Linux
/// members, which it dials (docs/protocol.md, section 9), and those that
/// come to it while it is the group's hub (MemberListener).
/// Each connection runs the member protocol of section 4: a hello first,
/// then events, a ping after 5 s without a write, and a close after 15 s
/// without a read.
public actor MemberNode {
    public let role: Member.Role
    public let name: String?
    /// This device's operating system, which the hellos state.
    public let os: String?
    /// This device's form, system version and version, which the hellos
    /// state too.
    public let device: Member.DeviceInfo?
    let engine: SyncEngine
    private var conns: [ObjectIdentifier: Conn] = [:]
    /// The commands sent that wait for their result, by command ID, with
    /// their receiver and the connections they went on.
    private var waiting: [String: (peer: String, conns: Set<ObjectIdentifier>, waiter: Waiter)] = [:]
    /// The commands passed on for other members, by command ID, until they
    /// expire (section 15): from is nil once the result went back.
    private var passed: [String: (from: ObjectIdentifier?, to: String, expiresMS: Int64)] = [:]
    /// The most commands passed on at a time, as Go.
    private static let maxPassed = 4096
    private let onChange: @Sendable (Member.Event) -> Void
    private let onCert: @Sendable (Data) -> Void
    private let records: RecordStore?
    private let renew: (@Sendable ([Data]) -> Renewal?)?
    private let adminCA: (@Sendable (Data) -> Data?)?
    private let onTunnel: @Sendable (String?, Member.TunnelOffer) -> Void
    private let hub: (@Sendable (String, Data, Data?, [Data]) -> [Member.TunnelOffer])?
    private let hubShare: (@Sendable (String, [Data]) -> Member.HubShare?)?
    private let onHubs: @Sendable (String, [Data], Member.HubShare) -> Void
    private let onCommand: (@Sendable (String?, Member.Record) -> Member.CommandResult)?
    private let onEvidence: @Sendable (String?, [Data], Member.Evidence) -> Void
    /// The images and files this phone holds whole, which it serves to its
    /// peers (section 4, "Content"); the hellos say so. nil serves none.
    private let content: ContentStore?
    /// The group's server credentials; nil keeps none and passes none on.
    private let credentials: CredentialKeeper?
    /// This phone's sync mode, which the hellos state; nil for a phone
    /// without one, which shares.
    public private(set) var mode: String?
    /// The WireGuard public key the hellos offer the group's hubs (section
    /// 11); nil while sync away from home is off.
    public private(set) var tunnelKey: Data?
    /// The preshared key this phone chose for its tunnels, which the hellos
    /// offer with tunnelKey (section 11, "Several hubs").
    public private(set) var tunnelPSK: Data?

    /// A renewed member certificate for a peer, DER, and the admin CA that
    /// issued it; nil when a root did.
    public struct Renewal: Equatable, Sendable {
        public var cert: Data
        public var issuer: Data?
        public init(cert: Data, issuer: Data? = nil) { (self.cert, self.issuer) = (cert, issuer) }
    }

    /// onChange gets the new current event when a peer's event becomes it;
    /// onCert gets a renewed member certificate a peer sent for this phone;
    /// records keeps the group's records and exchanges them with the peers;
    /// renew, on an admin phone, gets each peer's certificate chain (leaf
    /// first) after its hello and returns a renewal when it is due, which
    /// the peer then gets in a cert message (section 2); adminCA, on the
    /// root, gets the admin key a computer's hello offers and returns the
    /// admin CA this phone issued for it, which the computer then gets in
    /// an admin message, so one that missed it gets it again; tunnelKey and
    /// tunnelPSK are the keys the hellos offer the hubs, and onTunnel gets
    /// each valid offer a peer that may be a hub sends for them, its own or
    /// another hub's passed on, with the device ID the caller of serve
    /// named the peer by, unless hub is set; hub, on the phone while it is
    /// one of the group's hubs (docs/design.md, "The phone as the hub"),
    /// gets the device ID a peer was named by, the tunnel key and preshared
    /// key its hello offers (the preshared key nil from an older member)
    /// and its certificate chain (leaf first), and returns the offers the
    /// peer then gets in tunnel messages: this hub's own, then the other
    /// hubs' it passes on;
    /// hubShare, on a hub, returns what it shares with a peer after its
    /// hello (section 11, "Several hubs"), nil for nothing, and onHubs gets
    /// what a peer that may be a hub shared; mode is this phone's sync
    /// mode for the hellos, and onCommand carries out a command a peer sent
    /// (docs/protocol.md, section 15), with the device ID the caller of
    /// serve named the peer by, and returns the result the peer gets;
    /// without it every command is refused; onEvidence gets the evidence a
    /// peer sent (section 17, "Evidence"), with the device ID it was named
    /// by and its certificate chain; content holds the images and files
    /// this phone serves (section 4, "Content").
    public init(engine: SyncEngine, name: String?, role: Member.Role = .phone, os: String? = nil, device: Member.DeviceInfo? = nil,
                records: RecordStore? = nil,
                renew: (@Sendable ([Data]) -> Renewal?)? = nil,
                adminCA: (@Sendable (Data) -> Data?)? = nil,
                tunnelKey: Data? = nil,
                tunnelPSK: Data? = nil,
                hub: (@Sendable (String, Data, Data?, [Data]) -> [Member.TunnelOffer])? = nil,
                hubShare: (@Sendable (String, [Data]) -> Member.HubShare?)? = nil,
                onChange: @escaping @Sendable (Member.Event) -> Void = { _ in },
                onCert: @escaping @Sendable (Data) -> Void = { _ in },
                onTunnel: @escaping @Sendable (String?, Member.TunnelOffer) -> Void = { _, _ in },
                onHubs: @escaping @Sendable (String, [Data], Member.HubShare) -> Void = { _, _, _ in },
                mode: String? = nil,
                onCommand: (@Sendable (String?, Member.Record) -> Member.CommandResult)? = nil,
                onEvidence: @escaping @Sendable (String?, [Data], Member.Evidence) -> Void = { _, _, _ in },
                content: ContentStore? = nil,
                credentials: CredentialKeeper? = nil) {
        (self.engine, self.name, self.role, self.records, self.renew, self.adminCA, self.onChange, self.onCert) =
            (engine, name, role, records, renew, adminCA, onChange, onCert)
        (self.tunnelKey, self.tunnelPSK, self.onTunnel, self.hub, self.os, self.device) = (tunnelKey, tunnelPSK, onTunnel, hub, os, device?.cleaned)
        (self.hubShare, self.onHubs, self.mode, self.onCommand, self.onEvidence) = (hubShare, onHubs, mode, onCommand, onEvidence)
        (self.content, self.credentials) = (content, credentials)
    }

    /// Replaces the sync mode that the next connections' hellos state.
    public func set(mode: String?) { self.mode = mode }

    /// Replaces the tunnel keys that the next connections' hellos offer;
    /// nil offers none.
    public func set(tunnelKey: Data?, psk: Data? = nil) { (self.tunnelKey, tunnelPSK) = (tunnelKey, tunnelKey == nil ? nil : psk) }

    /// The current event with its age as of now.
    public var current: Member.Event? { engine.currentEvent }

    /// The current text while it is usable.
    public var usable: (text: String, kind: Member.Kind)? { engine.usable }

    /// The number of connections whose peer sent its hello.
    public var peers: Int { conns.values.filter { $0.peerRole != nil }.count }

    /// The device IDs of the connected members that sent their hello, where
    /// the caller of serve named them.
    public var connected: Set<String> {
        Set(conns.values.compactMap { $0.peerRole != nil ? $0.peer : nil })
    }

    /// The admin keys that the connected computers offer in their hello, by
    /// device ID, where the caller of serve named them: the computers the
    /// root can make admins (section 10, "A computer as admin").
    public var offeredAdminKeys: [String: Data] {
        var out: [String: Data] = [:]
        for c in conns.values { if let p = c.peer, let k = c.adminKey { out[p] = k } }
        return out
    }

    /// The quick actions the connected members' hellos say are on, by
    /// device ID, where the caller of serve named them.
    public var actions: [String: [String]] {
        var out: [String: [String]] = [:]
        for c in conns.values { if let p = c.peer, !c.actions.isEmpty { out[p] = c.actions } }
        return out
    }

    /// Where the connected members' hellos say their keys live, by device
    /// ID, where the caller of serve named them.
    public var keyStores: [String: String] {
        var out: [String: String] = [:]
        for c in conns.values { if let p = c.peer, let s = c.keyStore { out[p] = s } }
        return out
    }

    /// What the connected members' hellos say about their devices, their
    /// invalid fields dropped, by device ID where the caller of serve named
    /// them.
    public var devices: [String: Member.DeviceInfo] {
        var out: [String: Member.DeviceInfo] = [:]
        for c in conns.values { if let p = c.peer, let d = c.device { out[p] = d } }
        return out
    }

    /// The device IDs of the connected members whose hellos say they serve
    /// images and files, where the caller of serve named them.
    public var mediaPeers: [String] {
        conns.values.compactMap { $0.peerRole != nil && $0.peerMedia ? $0.peer : nil }
    }

    /// The sync modes the connected members' hellos report, by device ID
    /// where the caller of serve named them.
    public var modes: [String: String] {
        var out: [String: String] = [:]
        for c in conns.values { if let p = c.peer, let m = c.mode { out[p] = m } }
        return out
    }

    /// Sends the member peer a command signed for it (section 15) and waits
    /// for its result, at most timeout seconds: on the connection to peer,
    /// or, without one, to the connected members in via, the group's hubs,
    /// one of which passes it on. The other members never get it: a
    /// command's body, a paste's text among it, is signed but not
    /// encrypted. It throws when it reaches no member, the connection to
    /// peer ends first or no result comes in time.
    public func command(_ command: Member.Record, to peer: String, timeout: TimeInterval = 10, via: [String] = []) async throws -> Member.CommandResult {
        guard let id = Commands.id(of: command) else { throw Failure.refused("the command has no ID") }
        let helloed = conns.filter { $0.value.peer != nil && $0.value.peerRole != nil }
        var to = helloed.filter { $0.value.peer == peer }
        if to.isEmpty { to = helloed.filter { via.contains($0.value.peer ?? "") } }
        guard !to.isEmpty else { throw Failure.notConnected }
        let w = Waiter()
        waiting[id] = (peer, Set(to.keys), w)
        for c in to.values { c.enqueue(.command(command)) }
        let timer = Task {
            try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            w.resolve(.failure(Failure.timedOut))
        }
        defer {
            timer.cancel()
            if waiting[id]?.waiter === w { waiting[id] = nil }
        }
        return try await w.wait()
    }

    /// Sends each connected member the offer offerFor returns for it, the
    /// old hub passing on the new hub's offer (section 11, "Moving the
    /// hub"), and returns the members that got one.
    @discardableResult
    public func sendTunnel(_ offerFor: @Sendable (String) -> Member.TunnelOffer?) -> [String] {
        sendTunnels { offerFor($0).map { [$0] } ?? [] }
    }

    /// Sends each connected member the offers offerFor returns for it, and
    /// returns the members that got any.
    @discardableResult
    public func sendTunnels(_ offerFor: @Sendable (String) -> [Member.TunnelOffer]) -> [String] {
        var sent: [String] = []
        for c in conns.values {
            guard let p = c.peer, c.peerRole != nil else { continue }
            let offers = offerFor(p)
            for o in offers { c.enqueue(.tunnel(o)) }
            if !offers.isEmpty { sent.append(p) }
        }
        return sent
    }

    /// Sends each connected member what shareFor returns for it, its device
    /// ID and chain, as a hub's share.
    public func sendHubs(_ shareFor: @Sendable (String, [Data]) -> Member.HubShare?) {
        for c in conns.values {
            guard let p = c.peer, c.peerRole != nil, let h = shareFor(p, c.transport.peerChain) else { continue }
            c.enqueue(.hubs(h))
        }
    }

    /// Sends a computer the admin CA the root issued for it.
    public func send(adminCA: Data, to peer: String) {
        for c in conns.values where c.peer == peer && c.peerRole != nil { c.enqueue(.admin(adminCA)) }
    }

    /// Sends a text this phone copied to every connected member, or with
    /// media images or files whose content this phone's ContentStore
    /// holds, text their plain-text alternative.
    @discardableResult
    public func send(text: String, kind: Member.Kind, via: Member.Via = .phone, media: Media.Manifest? = nil) -> Member.Event {
        let e = engine.local(text: text, kind: kind, via: via, media: media)
        for c in conns.values { forward(e, to: c) }
        return e
    }

    /// Runs a connection whose TLS handshake is done until it ends, and
    /// closes it. It returns normally when the peer says goodbye or this
    /// side closed it (closeAll).
    public func serve(_ t: ClosableTransport, peer: String? = nil) async throws {
        let c = Conn(transport: t, peer: peer)
        let id = ObjectIdentifier(c)
        conns[id] = c
        // While the records stop the exchange with the peer, the
        // connection carries records only, so that the root's decision
        // reaches it (docs/protocol.md, section 10, "Stopping the exchange").
        c.recordsOnly = records?.stopped(chain: t.peerChain) ?? false
        var hello = engine.hello(name: name)
        if c.recordsOnly { hello.current = nil }
        hello.os = os
        hello.device = device
        hello.records = records?.digest
        hello.tunnelKey = tunnelKey
        hello.tunnelPSK = tunnelKey == nil ? nil : tunnelPSK
        hello.mode = mode
        // A phone's keys are in the Secure Enclave or the Keystore.
        hello.keyStore = Records.hardware
        hello.media = content != nil
        c.enqueue(.hello(role, hello))
        let writer = Task { await c.runWriter() }
        let watchdog = Task { await c.runWatchdog() }
        defer {
            conns[id] = nil
            for w in waiting.values where w.conns == [id] { w.waiter.resolve(.failure(Failure.closed)) }
            c.finish()
            c.endFetches()
            writer.cancel()
            watchdog.cancel()
            t.close()
        }
        var first = true
        while true {
            let m: Member.Message
            do {
                m = try await c.readMessage()
            } catch where c.closing {
                return // closed on this side; nothing more counts
            }
            if first {
                guard case let .hello(peerRole, h) = m else { throw Failure.noHello }
                first = false
                if let why = records?.refused(chain: t.peerChain) { throw Failure.refused(why) }
                if c.recordsOnly {
                    if let store = records, let mine = store.digest, mine != h.records {
                        for rs in Member.Record.chunks(store.all) { c.enqueue(.records(rs)) }
                    }
                    continue
                }
                c.adminKey = h.adminKey
                c.keyStore = h.keyStore
                c.actions = h.actions
                c.device = h.device?.cleaned
                c.mode = h.mode
                c.peerMedia = h.media
                c.peerRole = peerRole
                apply(try engine.reconcile(h), from: id)
                if let store = records, let mine = store.digest, mine != h.records {
                    for rs in Member.Record.chunks(store.all) { c.enqueue(.records(rs)) }
                }
                if let renew, !t.peerChain.isEmpty, let renewed = renew(t.peerChain) {
                    c.enqueue(.cert(renewed.cert, issuer: renewed.issuer))
                }
                if let key = h.adminKey, let ca = adminCA?(key) {
                    c.enqueue(.admin(ca))
                }
                if let hub, let p = c.peer, let key = h.tunnelKey, !t.peerChain.isEmpty {
                    let psk = h.tunnelPSK.flatMap { $0.count == 32 ? $0 : nil }
                    for offer in hub(p, key, psk, t.peerChain) { c.enqueue(.tunnel(offer)) }
                }
                if let hubShare, let p = c.peer, !t.peerChain.isEmpty, let share = hubShare(p, t.peerChain) {
                    c.enqueue(.hubs(share))
                }
                if let all = credentials?.all, !all.isEmpty { c.enqueue(.credentials(all)) }
                continue
            }
            if c.recordsOnly {
                if case let .records(rs) = m, let store = records, !rs.isEmpty, !store.add(rs).isEmpty {
                    dropRefused()
                } else if case .bye = m {
                    return
                }
                continue
            }
            switch m {
            case let .event(e?):
                apply(engine.received(e), from: id)
            case let .cert(der, _):
                onCert(der)
            case let .evidence(e) where !t.peerChain.isEmpty:
                onEvidence(c.peer, t.peerChain, e)
            // Only the root or an admin, by the records and its key.
            // A hub is no client yet: it gets the other hubs' offers in their shares.
            case let .tunnel(o?) where o.isValid && hub == nil:
                if let p = c.peer, records?.mayHost(p, chain: t.peerChain) != false { onTunnel(p, o) }
            case let .hubs(share):
                if let p = c.peer, records?.mayHost(p, chain: t.peerChain) != false { onHubs(p, t.peerChain, share) }
            case let .credentials(cs) where !cs.isEmpty && cs.count <= ServerCredentials.maxCredentials:
                if let fresh = credentials?.add(cs), !fresh.isEmpty { sendCredentials(fresh, except: id) }
            case let .records(rs):
                if let store = records, !rs.isEmpty {
                    let fresh = store.add(rs)
                    if !fresh.isEmpty {
                        sendRecords(fresh, except: id)
                        dropRefused()
                    }
                }
            case let .command(r):
                if let to = Commands.to(of: r), to != engine.device {
                    pass(r, from: id, to: to)
                } else {
                    var res = onCommand?(c.peer, r)
                        ?? Member.CommandResult(id: Commands.id(of: r) ?? "", status: "refused", reason: "this device takes no commands")
                    res.by = engine.device
                    c.enqueue(.result(res))
                }
            case var .result(r):
                r.reason = r.reason.map(Member.cleanReason)
                // A member the command went to so that it passes it on
                // answers only with the receiver's result.
                if let w = waiting[r.id], w.conns.contains(id), c.peer == w.peer || r.by == w.peer {
                    w.waiter.resolve(.success(r))
                } else if let p = passed[r.id], p.to == c.peer, let from = p.from {
                    passed[r.id]?.from = nil
                    conns[from]?.enqueue(.result(r))
                }
            case let .get(g):
                try get(g, on: c)
            case let .missing(g):
                c.fetching(g.sha256)?.end(Failure.missing)
            case let .chunk(ch):
                c.fetching(ch.sha256)?.push(ch)
            case .bye:
                return
            default:
                break // a ping, an event that did not decode, or a newer type
            }
        }
    }

    /// Fetches the part whose SHA-256 is sha256 and whose size is size from
    /// the connected peer, from offset on, and passes each piece to sink in
    /// order; it returns once the part is complete and throws when the peer
    /// does not hold it (Failure.missing), the connection ends, or the task
    /// is cancelled, which cancels it with the peer. It checks nothing of
    /// the content: the caller hashes what sink got. One fetch of a part
    /// runs on a connection at a time.
    public nonisolated func fetch(from peer: String, sha256 sum: Data, size: Int64, offset: Int64 = 0,
                                  sink: (Int64, Data) throws -> Void) async throws {
        guard let c = await conn(to: peer) else { throw Failure.notConnected }
        guard c.peerMedia else { throw Failure.refused("the device serves no images or files") }
        let f = Fetching()
        guard c.startFetch(sum, f) else { throw Failure.refused("this part is already being fetched from that device") }
        defer { c.stopFetch(sum, f) }
        let cancel = { c.enqueue(.get(Member.Get(sha256: sum, offset: 0, length: 0))) }
        var at = offset
        var asked = offset // the end of the ranges asked for
        func ask() {
            while asked < size, asked - at < Self.fetchAhead {
                let l = min(Member.getWindow, size - asked)
                c.enqueue(.get(Member.Get(sha256: sum, offset: asked, length: l)))
                asked += l
            }
        }
        ask()
        // A peer that stops sending ends the fetch, as Go's fetchStall.
        let stall = Task {
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                if f.idle(longer: Self.fetchStall) {
                    f.end(Failure.refused("the device sent nothing of the part for 15 seconds"))
                    return
                }
            }
        }
        defer { stall.cancel() }
        while at < size {
            if Task.isCancelled {
                cancel()
                throw CancellationError()
            }
            let ch: Member.Chunk
            do {
                ch = try await withTaskCancellationHandler { try await f.next() } onCancel: { f.end(CancellationError()) }
            } catch {
                // Missing, stalled or cancelled: the ranges asked for after
                // it may still be served, and would only cross the next
                // fetch.
                cancel()
                throw error
            }
            guard !ch.data.isEmpty, ch.offset + Int64(ch.data.count) <= size else {
                cancel()
                throw Failure.refused("the device sent a chunk that is not valid")
            }
            // Left from a fetch of the part cancelled before: the peer
            // serves gets in order, so the piece wanted comes later.
            guard ch.offset == at else { continue }
            do {
                try sink(at, ch.data)
            } catch {
                cancel()
                throw error
            }
            at += Int64(ch.data.count)
            ask()
        }
    }

    /// The most bytes a fetch keeps asked for ahead of what it has.
    static let fetchAhead: Int64 = 4 << 20
    /// How long a fetch waits for the next piece before it gives up.
    static let fetchStall: TimeInterval = 15
    /// The most gets a peer may have waiting on one connection.
    static let maxGets = 64
    /// How many chunks a connection holds ready to write.
    static let chunkQueue = 8

    private func conn(to peer: String) -> Conn? {
        conns.values.first { $0.peer == peer && $0.peerRole != nil }
    }

    /// Serves a peer's get: it queues the range for the connection's
    /// server, or cancels the queued ranges of the part.
    private func get(_ g: Member.Get, on c: Conn) throws {
        guard g.isValid else { return } // dropped, as Go does
        if g.length == 0 {
            c.cancelGets(g.sha256)
            return
        }
        guard let content, let src = content.open(sha256: g.sha256) else {
            c.enqueue(.missing(g))
            return
        }
        let size = src.size
        src.close()
        guard g.offset < size else {
            c.enqueue(.missing(g))
            return
        }
        switch c.queueGet(g) {
        case .tooMany: throw Failure.refused("the peer asks for too much at once")
        case .queued: break
        case .start: Task.detached { await Self.serveGets(on: c, from: content) }
        }
    }

    /// Reads the ranges the peer asked for, in order, and hands their
    /// chunks to the writer, until none is left or the connection ends.
    private static func serveGets(on c: Conn, from content: ContentStore) async {
        while let (g, cancels) = c.nextGet() {
            guard let src = content.open(sha256: g.sha256) else {
                c.enqueue(.missing(g))
                continue
            }
            defer { src.close() }
            let end = min(src.size, g.offset + g.length)
            var off = g.offset
            while off < end, !c.cancelled(g.sha256, since: cancels) {
                let n = Int(min(Int64(Member.chunkSize), end - off))
                guard let data = try? src.read(offset: off, length: n) else {
                    c.enqueue(.missing(g))
                    break
                }
                guard await c.put(chunk: Member.Chunk(sha256: g.sha256, offset: off, data: data)) else { return }
                off += Int64(n)
            }
        }
    }

    /// A fetch in progress on a connection: the chunks of its part, until
    /// the peer says it has none or the connection ends.
    final class Fetching: @unchecked Sendable {
        private let lock = NSLock()
        private var chunks: [Member.Chunk] = []
        private var ended: Error?
        private var waiter: CheckedContinuation<Void, Never>?
        private var last = Date()

        func push(_ c: Member.Chunk) {
            wake {
                last = Date()
                // The fetch asks for at most fetchAhead; a peer that sends
                // much more ends it.
                if chunks.count > Int(MemberNode.fetchAhead) / Member.chunkSize * 2 {
                    ended = ended ?? Failure.refused("the device sent chunks nobody asked for")
                } else {
                    chunks.append(c)
                }
            }
        }

        func end(_ e: Error) { wake { ended = ended ?? e } }

        /// Whether no chunk came for longer than t.
        func idle(longer t: TimeInterval) -> Bool { lock.withLock { Date().timeIntervalSince(last) > t } }

        private func wake(_ f: () -> Void) {
            let w: CheckedContinuation<Void, Never>? = lock.withLock {
                f()
                defer { waiter = nil }
                return waiter
            }
            w?.resume()
        }

        func next() async throws -> Member.Chunk {
            while true {
                let (c, e): (Member.Chunk?, Error?) = lock.withLock {
                    if !chunks.isEmpty { return (chunks.removeFirst(), nil) }
                    return (nil, ended)
                }
                if let c { return c }
                if let e { throw e }
                await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in
                    let ready = lock.withLock {
                        if !chunks.isEmpty || ended != nil { return true }
                        waiter = k
                        return false
                    }
                    if ready { k.resume() }
                }
            }
        }
    }

    /// Passes a command for the member to on, once by its ID, when to is
    /// connected, and later its result back (section 15). The receiver
    /// checks the signature, so this node can neither forge nor change it.
    private func pass(_ command: Member.Record, from: ObjectIdentifier, to: String) {
        let now = Records.ms(Date())
        passed = passed.filter { $0.value.expiresMS > now }
        guard let id = Commands.id(of: command), let exp = Commands.expires(of: command),
              exp > now, exp - now <= Commands.lifetimeMS + Commands.aheadMS,
              passed[id] == nil, passed.count < Self.maxPassed,
              let dst = conns.first(where: { $0.value.peer == to && $0.value.peerRole != nil }), dst.key != from
        else { return }
        passed[id] = (from, to, exp)
        dst.value.enqueue(.command(command))
    }

    /// Says goodbye on every connection and closes it.
    public func closeAll() {
        for c in conns.values { c.goodbye() }
    }

    /// Closes the connections to a device, for example one just removed.
    public func close(peer: String) {
        for c in conns.values where c.peer == peer { c.goodbye() }
    }

    /// Says goodbye, after what is queued for them, on the connections to
    /// peers, and waits up to timeout until they ended: an old hub's
    /// clients then have the new hub's offer before its tunnel stops.
    public func sayGoodbye(to peers: [String], timeout: Duration) async {
        let ids = conns.filter { $0.value.peer.map(peers.contains) == true }.map(\.key)
        for id in ids { conns[id]?.goodbye() }
        let deadline = ContinuousClock.now + timeout
        while ids.contains(where: { conns[$0] != nil }), ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(50))
        }
    }

    /// Sends records made on this phone to every connected member.
    public func sendRecords(_ rs: [Member.Record]) {
        sendRecords(rs, except: nil)
        dropRefused()
    }

    /// Closes the connections whose peers the records now refuse, as a
    /// device just removed.
    private func dropRefused() {
        guard let store = records else { return }
        for c in conns.values where store.refused(chain: c.transport.peerChain) != nil || store.stopped(chain: c.transport.peerChain) != c.recordsOnly {
            c.goodbye()
        }
    }

    /// Sends server credentials signed on this phone to every connected
    /// member.
    public func sendCredentials(_ cs: [ServerCredentials.Credential]) { sendCredentials(cs, except: nil) }

    private func sendCredentials(_ cs: [ServerCredentials.Credential], except: ObjectIdentifier?) {
        for (id, c) in conns where id != except && c.peerRole != nil { c.enqueue(.credentials(cs)) }
    }

    private func sendRecords(_ rs: [Member.Record], except: ObjectIdentifier?) {
        let chunks = Member.Record.chunks(rs)
        for (id, c) in conns where id != except && c.peerRole != nil {
            for part in chunks { c.enqueue(.records(part)) }
        }
    }

    /// Sends an event on c: none on a connection that carries records only,
    /// and the mark of a secret, never its text, to a peer the records stop
    /// secrets to (docs/protocol.md, section 10, "Stopping the exchange").
    private func forward(_ e: Member.Event, to c: Conn) {
        guard !c.recordsOnly else { return }
        var e = e
        if e.kind == .secret, let store = records {
            let leaf = c.transport.peerChain.first.flatMap { try? CertificateInfo(der: $0).commonName }
            if store.noSecrets(to: c.peer ?? leaf) { e.text = "" }
        }
        c.enqueue(.event(e))
    }

    private func apply(_ r: SyncEngine.Result, from: ObjectIdentifier) {
        if let e = r.forward {
            for (id, c) in conns where id != from { forward(e, to: c) }
        }
        if r.changed, let cur = engine.currentEvent { onChange(cur) }
    }

    public enum Failure: Error, Equatable {
        case noHello, timedOut, refused(String), notConnected, closed
        /// The peer does not hold the part whole.
        case missing
    }

    /// A command's result, which comes from the peer, a timeout or the end
    /// of the connection, whichever is first.
    final class Waiter: @unchecked Sendable {
        private let lock = NSLock()
        private var got: Swift.Result<Member.CommandResult, Error>?
        private var waiter: CheckedContinuation<Member.CommandResult, Error>?

        func resolve(_ r: Swift.Result<Member.CommandResult, Error>) {
            let w: CheckedContinuation<Member.CommandResult, Error>? = lock.withLock {
                guard got == nil else { return nil }
                got = r
                defer { waiter = nil }
                return waiter
            }
            w?.resume(with: r)
        }

        func wait() async throws -> Member.CommandResult {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Member.CommandResult, Error>) in
                let r: Swift.Result<Member.CommandResult, Error>? = lock.withLock {
                    if let got { return got }
                    waiter = c
                    return nil
                }
                if let r { c.resume(with: r) }
            }
        }
    }

    /// One connection: a queue the writer drains, and the times of the
    /// last read and write for the ping and the timeout.
    final class Conn: @unchecked Sendable {
        let transport: ClosableTransport
        /// The peer's device ID, when the dialer knows it.
        let peer: String?
        private let lock = NSLock()
        private var queue: [Member.Message] = []
        /// The chunks ready to write, which go out only while no message
        /// waits; a server waits in space while chunkQueue are there.
        private var chunks: [Member.Chunk] = []
        private var waiter: CheckedContinuation<Void, Never>?
        private var space: CheckedContinuation<Void, Never>?
        /// The peer's gets waiting to be served, each with its part's
        /// cancels when it came, and whether a server runs.
        private var gets: [(Member.Get, Int)] = []
        private var serving = false
        /// The SHA-256 of the part the server serves now.
        private var current: Data?
        /// The peer's cancels of each part, so that a range queued before a
        /// cancel ends with its next chunk, while one asked for after it
        /// goes on.
        private var cancels: [Data: Int] = [:]
        /// The fetches of this side waiting for chunks, by their part's
        /// SHA-256.
        private var fetches: [Data: Fetching] = [:]
        /// Whether the peer's hello says it serves content.
        var peerMedia: Bool {
            get { lock.withLock { _peerMedia } }
            set { lock.withLock { _peerMedia = newValue } }
        }
        private var _peerMedia = false
        private var done = false
        private var sayBye = false
        private var lastRead = ProcessInfo.processInfo.systemUptime
        private var lastWrite = ProcessInfo.processInfo.systemUptime
        var peerRole: Member.Role? {
            get { lock.withLock { _peerRole } }
            set { lock.withLock { _peerRole = newValue } }
        }
        private var _peerRole: Member.Role?
        /// The admin key the peer's hello offered.
        var adminKey: Data? {
            get { lock.withLock { _adminKey } }
            set { lock.withLock { _adminKey = newValue } }
        }
        private var _adminKey: Data?
        /// Where the peer's hello says its keys live.
        var keyStore: String? {
            get { lock.withLock { _keyStore } }
            set { lock.withLock { _keyStore = newValue } }
        }
        private var _keyStore: String?
        /// Whether the records stop the exchange with the peer, which then
        /// carries records only.
        var recordsOnly: Bool {
            get { lock.withLock { _recordsOnly } }
            set { lock.withLock { _recordsOnly = newValue } }
        }
        private var _recordsOnly = false
        /// The quick actions the peer's hello says are on.
        var actions: [String] {
            get { lock.withLock { _actions } }
            set { lock.withLock { _actions = newValue } }
        }
        private var _actions: [String] = []
        /// What the peer's hello says about its device.
        var device: Member.DeviceInfo? {
            get { lock.withLock { _device } }
            set { lock.withLock { _device = newValue } }
        }
        private var _device: Member.DeviceInfo?
        /// The sync mode the peer's hello reports.
        var mode: String? {
            get { lock.withLock { _mode } }
            set { lock.withLock { _mode = newValue } }
        }
        private var _mode: String?

        init(transport: ClosableTransport, peer: String?) { (self.transport, self.peer) = (transport, peer) }

        func enqueue(_ m: Member.Message) {
            let w: CheckedContinuation<Void, Never>? = lock.withLock {
                guard !done else { return nil }
                queue.append(m)
                defer { waiter = nil }
                return waiter
            }
            w?.resume()
        }

        /// Queues a chunk, waiting while chunkQueue wait; it returns false
        /// once the connection ended.
        func put(chunk: Member.Chunk) async -> Bool {
            while true {
                let (added, isDone): (Bool, Bool) = lock.withLock {
                    if done { return (false, true) }
                    if chunks.count < MemberNode.chunkQueue {
                        chunks.append(chunk)
                        return (true, false)
                    }
                    return (false, false)
                }
                if isDone { return false }
                if added {
                    let w: CheckedContinuation<Void, Never>? = lock.withLock {
                        defer { waiter = nil }
                        return waiter
                    }
                    w?.resume()
                    return true
                }
                await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                    let ready = lock.withLock {
                        if done || chunks.count < MemberNode.chunkQueue { return true }
                        space = c
                        return false
                    }
                    if ready { c.resume() }
                }
            }
        }

        enum Queued { case start, queued, tooMany }

        /// Queues a get for the server; start says to start one.
        func queueGet(_ g: Member.Get) -> Queued {
            lock.withLock {
                guard gets.count < MemberNode.maxGets else { return .tooMany }
                gets.append((g, cancels[g.sha256] ?? 0))
                if serving { return .queued }
                serving = true
                return .start
            }
        }

        /// The next get to serve, or nil when none is left, which ends the
        /// server.
        func nextGet() -> (Member.Get, Int)? {
            lock.withLock {
                if gets.isEmpty || done {
                    serving = false
                    current = nil
                    cancels = [:]
                    return nil
                }
                let g = gets.removeFirst()
                current = g.0.sha256
                return g
            }
        }

        /// Drops the queued gets of a part, and ends the one being served.
        func cancelGets(_ sum: Data) {
            lock.withLock {
                let before = gets.count
                gets.removeAll { $0.0.sha256 == sum }
                // Only a part queued or being served is counted, as Go does,
                // so that cancels of other parts cannot fill the map.
                if serving, gets.count < before || current == sum { cancels[sum, default: 0] += 1 }
            }
        }

        func cancelled(_ sum: Data, since n: Int) -> Bool { lock.withLock { (cancels[sum] ?? 0) != n } }

        /// How many parts the peer's cancels are kept for.
        var cancelledParts: Int { lock.withLock { cancels.count } }

        func fetching(_ sum: Data) -> Fetching? { lock.withLock { fetches[sum] } }

        func startFetch(_ sum: Data, _ f: Fetching) -> Bool {
            lock.withLock {
                if done { f.end(Failure.closed) }
                guard fetches[sum] == nil else { return false }
                fetches[sum] = f
                return true
            }
        }

        func stopFetch(_ sum: Data, _ f: Fetching) {
            lock.withLock { if fetches[sum] === f { fetches[sum] = nil } }
        }

        /// Ends the fetches waiting on this connection.
        func endFetches() {
            for f in lock.withLock({ Array(fetches.values) }) { f.end(Failure.closed) }
        }

        /// Whether this side ended the connection.
        var closing: Bool { lock.withLock { sayBye } }

        /// Ends the writer, after a goodbye.
        func goodbye() {
            lock.withLock { sayBye = true }
            finish()
        }

        func finish() {
            let (w, s): (CheckedContinuation<Void, Never>?, CheckedContinuation<Void, Never>?) = lock.withLock {
                done = true
                defer { (waiter, space) = (nil, nil) }
                return (waiter, space)
            }
            w?.resume()
            s?.resume()
        }

        private func next() async -> Member.Message? {
            while true {
                let (m, isDone, s): (Member.Message?, Bool, CheckedContinuation<Void, Never>?) = lock.withLock {
                    if !queue.isEmpty { return (queue.removeFirst(), false, nil) }
                    if done { return (nil, true, nil) }
                    if !chunks.isEmpty {
                        defer { space = nil }
                        return (.chunk(chunks.removeFirst()), false, space)
                    }
                    return (nil, false, nil)
                }
                s?.resume()
                if let m { return m }
                if isDone { return nil }
                await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                    let ready = lock.withLock {
                        if !queue.isEmpty || !chunks.isEmpty || done { return true }
                        waiter = c
                        return false
                    }
                    if ready { c.resume() }
                }
            }
        }

        func runWriter() async {
            while let m = await next() {
                do {
                    try await transport.write(Member.encode(m))
                    lock.withLock { lastWrite = ProcessInfo.processInfo.systemUptime }
                } catch {
                    transport.close()
                    return
                }
            }
            if lock.withLock({ sayBye }) {
                try? await transport.write(Member.encode(.bye))
                transport.close()
            }
        }

        /// Sends a ping after a quiet write side, and closes a connection
        /// silent for the timeout.
        func runWatchdog() async {
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 500_000_000)
                let now = ProcessInfo.processInfo.systemUptime
                let (r, w) = lock.withLock { (lastRead, lastWrite) }
                if now - r > Member.timeout {
                    transport.close()
                    return
                }
                if now - w >= Member.pingEvery {
                    lock.withLock { lastWrite = now } // one ping per quiet spell
                    enqueue(.ping)
                }
            }
        }

        func readMessage() async throws -> Member.Message {
            let (n, binary) = try Member.header(try await transport.read(exactly: 4))
            let body = try await transport.read(exactly: n)
            lock.withLock { lastRead = ProcessInfo.processInfo.systemUptime }
            return binary ? .chunk(try Member.decodeChunk(body: body)) : try Member.decode(body: body)
        }
    }
}
