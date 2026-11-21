// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import CryptoKit
import Foundation
import LocalAuthentication
import Network
import os
import Security
import UIKit
import UniformTypeIdentifiers

private let relayLog = Logger(subsystem: "tools.cbb", category: "relay")
private let browseLog = Logger(subsystem: "tools.cbb", category: "browse")
private let pairLog = Logger(subsystem: "tools.cbb", category: "pair")
private let hubLog = Logger(subsystem: "tools.cbb", category: "hub")
private let modeLog = Logger(subsystem: "tools.cbb", category: "mode")
private let keysLog = Logger(subsystem: "tools.cbb", category: "keys")
private let imageLog = Logger(subsystem: "tools.cbb", category: "images")
private let syncLog = Logger(subsystem: "tools.cbb", category: "sync")

/// The phone's own group (docs/protocol.md, section 9): its root CA key in
/// the Secure Enclave, signing only after Face ID or the passcode (a
/// keychain key where there is no Secure Enclave, as in the simulator), its
/// member key in the keychain, the group in Application Support. While there is a group it finds the computers,
/// keeps a connection to each, and syncs with them.
@MainActor
final class LiveGroup: GroupController {
    /// Something in the member broke (a `panic` event): what broke and the
    /// member's recent log lines, oldest first, for the bug report
    /// (docs/core-api.md, "Bug reports"); the member starts again by itself.
    var onPanic: ((String, [String]) -> Void)?
    /// The member's recent log lines, for a bug report.
    private var recentLog: [String] = []
    enum Failure: Error, Equatable { case unreachable, notConfirmed, noNetwork, timedOut, tooManyWrongCodes, notAdmin, noWindow, twoWindows, needsRoot, noGroup, rootLeaves([String]), hubUnreachable }

    /// The clipboard holds something the app could not read as text: the
    /// paste was not allowed, or it is not text. The button leaves it as it
    /// is rather than put an older text over it.
    /// A device refused a command (docs/protocol.md, section 15), saying
    /// why.
    struct CommandRefused: Error { let reason: String }

    struct ClipboardUnreadable: Error {
        let items: Int
        let hasStrings: Bool
        let types: [String]
        let changeCount: Int
    }

    nonisolated static let caLabel = "tools.cbb.group-root"
    /// The admin key of a phone that joined another phone's group.
    nonisolated static let adminLabel = "tools.cbb.admin"
    /// How long joinComputer browses for a pairing window, and then for a
    /// second one.
    static let browseFor: TimeInterval = 10
    static let pairingSettle: TimeInterval = 2
    /// How long one Face ID check covers the root key's signatures for the
    /// actions that follow it.
    static let authorizedFor: TimeInterval = 300
    static let memberLabel = Shared.memberLabel
    /// Whether the root and admin keys live in the Secure Enclave behind
    /// Face ID. The simulator reports a Secure Enclave but cannot make a key
    /// that needs user presence, so there they are keychain keys.
    nonisolated static var secureEnclave: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return SecureEnclave.isAvailable
        #endif
    }
    /// How long the button waits for a computer to connect before it says
    /// none is.
    static let connectWait: Duration = .seconds(5)

    let file: URL
    /// The revocation list the root checks evidence against.
    private let attestStatus: AttestStatus
    private(set) var state: PhoneGroup?
    /// The phone's member in the Rust core, which syncs (docs/core-api.md,
    /// "The member"), and the task that takes its events.
    private var node: CoreMember?
    private var events: Task<Void, Never>?
    private var browser: BonjourBrowser?
    private var relay: Relay?
    private var recordBox: RecordBox?
    /// The group's server credentials (docs/protocol.md, section 18) and
    /// this phone's keys for the servers.
    private var credentialBox: CredentialBox?
    private let periodKeys = PhoneKeys()
    private var renewer: Renewer?
    private var admins: AdminBox?
    /// While the phone is the group's hub on a home network, the member's
    /// port on every address, published by Bonjour.
    private var homePort: UInt16?
    private var publisher: BonjourPublisher?
    /// On a group of 0.6, what the user chose for the hub; the Live member
    /// runs sync away from home, the hub and the relay itself (AwayOn06).
    private var hub06 = Hub06Keychain.load() ?? AwayOn06.Prefs()
    /// Whether the app is in front: the phone is the hub only then (iOS
    /// gives an app no way to keep it running in the background).
    private var foreground = false
    /// Whether the app is in the background, where the member closes its
    /// connections and makes none, but for a background refresh.
    private var background = false
    /// The network the phone is on, as the hub remembers home networks.
    private var network: String?
    private let paths = NWPathMonitor()
    /// The hub's changes, one after another.
    private var hubWork: Task<Void, Never>?
    private var online: Set<String> = []
    /// The devices the connected computers reach, not connected here.
    private var reached: Set<String> = []
    /// The admin keys the connected computers offer, by device ID.
    private var offers: [String: Data] = [:]
    /// Where the connected members' hellos say their keys live.
    private var keyStores: [String: String] = [:]
    /// What the connected members' hellos say about their devices.
    private var infos: [String: Member.DeviceInfo] = [:]
    /// The sync modes the connected members' hellos report.
    private var modes: [String: String] = [:]
    /// The mutes the connected members' hellos report: until when, 0 for
    /// until an admin lifts it.
    private var mutes: [String: Int64] = [:]
    /// The quick actions the connected members' hellos say are on.
    private var actions: [String: [String]] = [:]
    /// This phone's own sync mode and the commands it took.
    let modeBox: ModeBox

    /// What this phone says about itself in its hellos: an iPhone or an
    /// iPad, its iOS and the app's version; iOS gives apps no MAC address.
    static var ownDevice: Member.DeviceInfo {
        Member.DeviceInfo(form: UIDevice.current.userInterfaceIdiom == .pad ? "tablet" : "phone",
                          osVersion: UIDevice.current.systemVersion,
                          version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String)
    }
    /// The last authentication context the user passed for the root key.
    /// The user's last Face ID check, good for authorizedFor; the renewer
    /// shares it, so both stop signing when it ends.
    private let authorization = Authorization(lasts: LiveGroup.authorizedFor)

    /// In the app group's container, where the share extension reads it.
    nonisolated static var defaultFile: URL { Shared.groupFile }

    init(file: URL = LiveGroup.defaultFile) {
        self.file = file
        attestStatus = AttestStatus(dir: file.deletingLastPathComponent().appendingPathComponent("attest-status"))
        modeBox = ModeBox(url: file.deletingLastPathComponent().appendingPathComponent("mode"))
        state = try? PhoneGroup.load(from: file)
        try? startSync()
        Task { await renewOwnCertificate() }
        // A new network may be a home network of the hub, or no longer be one.
        paths.pathUpdateHandler = { [weak self] path in
            let key = Self.networkKey(path)
            Task { @MainActor in
                self?.network = key
                self?.refreshHub()
            }
        }
        paths.start(queue: DispatchQueue(label: "cbb.paths"))
        // The phone locked with the app in front: the keys sign without
        // asking no more, as when the app goes to the background.
        let authorization = authorization
        NotificationCenter.default.addObserver(forName: UIApplication.protectedDataWillBecomeUnavailableNotification,
                                               object: nil, queue: nil) { _ in authorization.end() }
    }

    /// The network of path as the hub remembers it (HubState.networkKey):
    /// Wi-Fi or Ethernet with an IPv4 gateway, never a mobile network.
    nonisolated static func networkKey(_ path: NWPath) -> String? {
        guard path.status == .satisfied,
              let interface = path.availableInterfaces.first(where: { $0.type == .wifi || $0.type == .wiredEthernet }),
              path.usesInterfaceType(interface.type) else { return nil }
        let gateway = path.gateways.lazy.compactMap { e -> String? in
            if case .hostPort(let host, _) = e, case .ipv4(let a) = host { return "\(a)" }
            return nil
        }.first
        guard let local = LocalAddresses.ipv4(interface: interface.name) else { return nil }
        return HubState.networkKey(gateway: gateway, address: local.address, prefixLength: local.prefixLength)
    }

    /// Renews this phone's own member certificate when it is due, which
    /// asks for Face ID, and then connects again with it.
    private func renewOwnCertificate() async {
        guard var g = state, GroupCertificates.isDue(g.memberCert, groupCA: g.adminCA ?? g.currentRoot, now: Date()),
              let ca = try? await caSigner(reason: String(localized: "Renew this phone's certificate", bundle: .app)),
              (try? g.renewOwnCertificate(caSigner: ca, now: Date())) == true else { return }
        try? g.save(to: file)
        state = g
        await restartSync()
    }

    var hasGroup: Bool { state != nil }

    var groupTag: String? { state?.tag }

    /// The member's tiles (docs/apps.md, "What the member shows").
    func view(_ op: Arrangement.Op?) throws -> Arrangement.View<CoreMember.TileDevice>? {
        try node?.view(op)
    }

    /// Whether this phone may add and remove devices: it made the group, or
    /// the phone that did made it an admin. A phone without a group makes
    /// one when it adds a computer.
    var isAdmin: Bool { state?.isAdmin ?? true }
    var isRoot: Bool { state?.isRoot ?? false }
    var handedOver: Bool { state?.handedToMe ?? false }
    var alerts: [GroupAlert] { state?.records.alerts ?? [] }

    /// When the counting recovery record was signed, from its body; kept
    /// for its key, since the app asks on every refresh.
    var recoveryMade: Date? {
        guard let g = state, let key = g.records.recovery else { return nil }
        if let c = recoveryTime, c.key == key { return c.at }
        let at = Self.recoveryMade(of: key, in: g.records.records)
        recoveryTime = (key, at)
        return at
    }

    private var recoveryTime: (key: Data, at: Date?)?

    private static func recoveryMade(of key: Data, in records: [Member.Record]) -> Date? {
        for r in records.reversed() {
            guard let o = try? JSONSerialization.jsonObject(with: r.body) as? [String: Any], o["type"] as? String == "recovery",
                  let admin = (o["admin"] as? String).flatMap({ Data(base64Encoded: $0) }), admin == key,
                  let ms = (o["time_ms"] as? NSNumber)?.int64Value else { continue }
            return Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        }
        return nil
    }

    /// Makes the group's recovery key (docs/protocol.md, section 10, "The
    /// recovery key"): the root key, after Face ID, issues it an admin CA and
    /// signs the recovery record, which every member gets. The key itself
    /// leaves only on its sheet.
    func makeRecovery() async throws -> Core.RecoverySheet {
        guard state?.isRoot == true else { throw PhoneGroup.Failure.notRoot }
        let root = try await caSigner(reason: String(localized: "Make a recovery key", bundle: .app))
        return try rootRecord(root) { n, p, s in try n.makeRecovery(public: p, sign: s) }
    }

    /// Has the phone's member in the core build, check and sign one of the
    /// root's own records with the root key (cbb_core::root), which it adds
    /// and sends, then takes the member's records into the group.
    @discardableResult
    private func rootRecord<T>(_ root: SecKeySigner, _ act: (CoreMember, Data, @escaping (Data) throws -> Data) throws -> T) throws -> T {
        guard let node else { throw CoreMember.Failure.notConnected }
        let out = try act(node, root.publicKeyDER, { try root.signature(digest: $0) })
        pullRecords()
        groupChanged()
        return out
    }

    var keyLevel: String? { state?.isRoot == true ? state?.keyLevel : nil }

    /// How long a copy from another device stays live after it arrives, in
    /// milliseconds, as the group's records set it.
    var incomingMS: Int64 { state?.incomingMS ?? Records.defaultIncomingMS }

    /// Sets how long a copy from another device stays live after it
    /// arrives: a copies record, signed after Face ID by the root or an
    /// admin and sent to every member (docs/protocol.md, section 10, "The
    /// copies setting").
    func setIncoming(ms: Int64) async throws {
        guard state?.isAdmin == true else { throw PhoneGroup.Failure.notAdmin }
        let ca = try await caSigner(reason: String(localized: "Change how long a copy from another device lasts", bundle: .app))
        guard var g = state else { throw PhoneGroup.Failure.notAdmin }
        let r = try g.setIncoming(ms: ms, caSigner: ca, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        sendRecords([r])
    }

    /// Sets the group's key level (docs/guide/keys.md, "The three levels"):
    /// a settings record, signed with the root key after Face ID and sent
    /// to every member, which keeps the takeover delay.
    func setKeyLevel(_ level: String) async throws {
        guard state?.isRoot == true else { throw PhoneGroup.Failure.notRoot }
        let root = try await caSigner(reason: String(localized: "Change which keys may be admins", bundle: .app))
        let own = state.flatMap { g in g.devices.first(where: { $0.id == g.device })?.store } ?? Records.hardware
        guard Records.levelAllows(level, store: own, consent: true) else { throw PhoneGroup.Failure.belowKeyLevel }
        try rootRecord(root) { n, p, s in try n.setKeyLevel(level, public: p, sign: s) }
    }

    /// Removes the group's recovery key: a revocation of it, signed with the
    /// root key after Face ID and sent to every member.
    func removeRecovery() async throws {
        guard state?.isRoot == true else { throw PhoneGroup.Failure.notRoot }
        let root = try await caSigner(reason: String(localized: "Remove the recovery key", bundle: .app))
        try rootRecord(root) { n, p, s in try n.removeRecovery(public: p, sign: s) }
    }

    /// The label of the key this phone signs with: the root key, or the
    /// admin key of a phone that joined.
    nonisolated static func signingLabel(_ g: PhoneGroup?) -> String { g?.isRoot == false ? adminLabel : caLabel }

    var computers: [AppModel.Computer] {
        devices.filter { !$0.isSelf }
    }

    var devices: [AppModel.Computer] {
        guard let g = state else { return [] }
        if g.isV06 { return devices06(g) }
        let root = g.records.rootDevice
        return g.devices.map {
            .init(id: $0.id, name: $0.name, online: $0.id == g.device || online.contains($0.id) || reached.contains($0.id),
                  throughHub: $0.id != g.device && !online.contains($0.id) && reached.contains($0.id), role: $0.role, caps: $0.caps, os: $0.os,
                  isSelf: $0.id == g.device,
                  admin: $0.admin || $0.id == root, isRoot: $0.id == root,
                  canMakeAdmin: g.isRoot && $0.id != root && !$0.admin && !$0.frozen && ($0.role == "phone" || $0.can("admin"))
                      && offers[$0.id] != nil,
                  keysInFile: Records.store(keyStores[$0.id] ?? $0.store, role: $0.role) == Records.file,
                  rootless: Records.store(keyStores[$0.id] ?? $0.store, role: $0.role) == Records.rootless, frozen: $0.frozen,
                  device: $0.id == g.device ? Self.ownDevice : infos[$0.id], mode: $0.id == g.device ? modeBox.mode : modes[$0.id],
                  actions: actions[$0.id] ?? [], mayHub: g.records.mayHost($0.id), forwardOnly: $0.forwardOnly,
                  muted: AppModel.Hold(ms: $0.id == g.device ? modeBox.mutedUntilMS : mutes[$0.id]),
                  syncOff: $0.id == g.device && modeBox.mode == "own" ? AppModel.Hold(ms: modeBox.syncOffUntilMS ?? 0) : nil)
        }
    }

    func refresh() async {
        take(peers: (try? node?.peers()) ?? [])
        if state?.isV06 == true, let gs = try? node?.group() {
            group06 = gs
            state?.admin06 = gs.me.admin
        }
        pullRecords()
        if let n = node, let ns = try? n.notices() { notices = ns }
        entries.reload()
        await finishTakeOverIfDue()
    }

    // MARK: The group in 0.6

    /// The member's state of a group of 0.6, as the last refresh read it.
    private var group06: GroupState?

    var isV06: Bool { state?.isV06 ?? false }

    /// The devices of a group of 0.6, as its member's state names them,
    /// with what the connected ones' hellos say.
    private func devices06(_ g: PhoneGroup) -> [AppModel.Computer] {
        guard let gs = group06 else { return [] }
        return gs.devices.map {
            let me = $0.device == g.device
            return .init(id: $0.device, name: $0.name, online: me || online.contains($0.device), role: $0.role == "computer" ? "member" : $0.role,
                         os: $0.os.isEmpty ? nil : $0.os, isSelf: me, admin: $0.admin, isRoot: $0.device == gs.rootDevice,
                         keysInFile: keyStores[$0.device] == Records.file, frozen: $0.frozen,
                         device: me ? Self.ownDevice : infos[$0.device], mode: me ? modeBox.mode : modes[$0.device],
                         actions: actions[$0.device] ?? [],
                         muted: AppModel.Hold(ms: me ? modeBox.mutedUntilMS : mutes[$0.device]),
                         syncOff: me && modeBox.mode == "own" ? AppModel.Hold(ms: modeBox.syncOffUntilMS ?? 0) : nil)
        }
    }

    /// Makes a group of 0.6 on this phone (docs/apps.md, "Screens"): a new
    /// root key in the Secure Enclave behind Face ID, the core writes this
    /// phone's record under it and keeps the set where the member runs, and
    /// the member starts. Returns the recovery sheet, which the app shows
    /// once and keeps nowhere.
    func newGroup06() async throws -> Core.RecoverySheet {
        guard state == nil else { throw Failure.noGroup }
        let root = try await newRootKey(reason: String(localized: "Add a computer to your group", bundle: .app))
        let member = try memberSigner()
        try FileManager.default.createDirectory(at: memberDir, withIntermediateDirectories: true)
        let made = try CorePairing.newGroup06(dir: memberDir, name: PhoneGroup.validName(UIDevice.current.name), store: Records.hardware,
                                              rootPublic: root.publicKeyDER, publicKey: member.publicKeyDER) { try root.signature(digest: $0) }
        let g = PhoneGroup.of06(device: made.device, group: made.group, root: true)
        try g.save(to: file)
        try modeBox.newDevice()
        forgetCredentials()
        state = g
        try startSync()
        groupChanged()
        await refresh()
        let text = made.recovery.text.flatMap { $0.split(separator: " ").map(String.init) }.joined(separator: "-")
        return Core.RecoverySheet(qr: made.recovery.qr, text: text, admin: Data())
    }

    /// Opens this phone's home window on a group of 0.6 (docs/protocol.md,
    /// "Pairing in 0.6"): the member port listens, the window is announced
    /// by Bonjour, and shown gets the QR code and the six digits. A device
    /// that dials proves the digits; nobody is asked. Returns the name of
    /// the device that joined; the window closes when it does, when its
    /// time is up, after three wrong codes, or when the task is cancelled.
    func openWindow(shown: @escaping @MainActor (_ qr: String, _ digits: String) -> Void) async throws -> String {
        guard let g = state, g.isV06, g.isAdmin else { throw Failure.noGroup }
        guard let node else { throw Failure.unreachable }
        let signer = try await caSigner(reason: String(localized: "Add a computer to your group", bundle: .app))
        let port: UInt16
        if let p = homePort { port = p } else { port = try node.listen(.home, port: 0) }
        let hosts = LocalAddresses.current()
        guard !hosts.isEmpty else { throw Failure.noNetwork }
        let w = try CorePairing.Window(member: node, publicKey: signer.publicKeyDER, addrs: hosts) { try signer.signature(digest: $0) }
        defer { w.close() }
        let announced = try? BonjourPublisher(name: g.device, port: port, txt: Discovery.windowTXT(group: g.tag, fingerprint: w.fingerprint, id: w.id))
        defer { announced?.stop() }
        shown(w.qr, w.digits)
        var version: UInt64 = 0
        while true {
            try Task.checkCancellation()
            let v = version
            let st = try await Task.detached { try w.next(after: v) }.value
            version = st.version
            switch st.state {
            case "done":
                await refresh()
                return st.name
            case "closed":
                throw st.failure ?? Failure.timedOut
            case "failed":
                if let f = st.failure { pairLog.error("a device did not join through the window: \(String(reflecting: f), privacy: .public)") }
            default:
                break
            }
        }
    }

    /// Joins a group of 0.6 by a home window's QR code, or by the six
    /// digits the person typed (qr empty: the one window Bonjour finds):
    /// this phone dials, proves the digits, and the member starts on the
    /// group it keeps.
    func joinByWindow(_ qr: String, digits: String = "") async throws {
        guard state == nil else { return }
        let member = try memberSigner()
        try FileManager.default.createDirectory(at: memberDir, withIntermediateDirectories: true)
        let code = qr.isEmpty ? try await findHomeWindow(digits: digits) : qr
        let j = try CorePairing.Joiner(dir: memberDir, qr: code, name: PhoneGroup.validName(UIDevice.current.name), os: "ios",
                                       publicKey: member.publicKeyDER) { try member.signature(digest: $0) }
        try await follow(j, invite: false)
    }

    /// Follows a joiner to its end: on done the member starts on the group
    /// it keeps; by an invitation, a hub that never answered is
    /// hubUnreachable.
    private func follow(_ j: CorePairing.Joiner, invite: Bool) async throws {
        defer { j.close() }
        var version: UInt64 = 0
        var answered = false
        while true {
            try Task.checkCancellation()
            let v = version
            let st = try await Task.detached { try j.next(after: v) }.value
            version = st.version
            answered = answered || st.answered
            switch st.state {
            case "done":
                let g = PhoneGroup.of06(device: st.device, group: st.group, root: false)
                try g.save(to: file)
                try modeBox.newDevice()
                forgetCredentials()
                state = g
                try startSync()
                groupChanged()
                await refresh()
                return
            case "failed":
                if invite && !answered { throw Failure.hubUnreachable }
                if let f = st.failure { throw f }
                throw Failure.unreachable
            default:
                break
            }
        }
    }

    /// The member's notices about the group, as the last refresh read them.
    private(set) var notices: [Notice] = []

    /// The change of root the member told of last, until the person saw it.
    private(set) var rootChanged: AppModel.RootChange?

    func dismissNotice(_ id: String) async throws {
        guard let n = node else { throw Failure.unreachable }
        try n.dismiss(id)
        notices = (try? n.notices()) ?? notices.filter { $0.id != id }
    }

    func rootChangeSeen() { rootChanged = nil }

    /// A device's name as the group's devices show it, else its ID.
    private func name(of id: String) -> String { devices.first { $0.id == id }?.name ?? id }

    func changePreview(_ recovery: RecoveryInput, leaveOut: [String]) async throws -> ChangePreview {
        guard let n = node else { throw Failure.unreachable }
        return try n.changePreview(recovery, leaveOut: leaveOut)
    }

    /// Moves the group's root to this phone (docs/design.md, "Changing the
    /// root"): a new root key in the Secure Enclave behind Face ID, and the
    /// member signs the change with the recovery key and the new root's
    /// first records with that key.
    func changeRoot(_ recovery: RecoveryInput, leaveOut: [String], overWaiting: Bool) async throws {
        guard let n = node else { throw Failure.unreachable }
        let root = try await newRootKey(reason: String(localized: "Make this phone the group's main device", bundle: .app))
        try n.changeRoot(recovery, leaveOut: leaveOut, rootPublic: root.publicKeyDER, overWaiting: overWaiting) { try root.signature(digest: $0) }
        notices = (try? n.notices()) ?? notices
    }

    /// Keeps what the connected members' hellos and reach messages say.
    private func take(peers ps: [CoreMember.Peer]) {
        online = Set(ps.map(\.device))
        reached = Set(ps.flatMap(\.reach)).subtracting(online).subtracting(state.map { [$0.device] } ?? [])
        infos = Dictionary(ps.compactMap { p in p.info.map { (p.device, $0) } }, uniquingKeysWith: { a, _ in a })
        modes = Dictionary(ps.compactMap { p in p.mode.isEmpty ? nil : (p.device, p.mode) }, uniquingKeysWith: { a, _ in a })
        mutes = Dictionary(ps.compactMap { p in p.mutedUntilMS().map { (p.device, $0) } }, uniquingKeysWith: { a, _ in a })
        actions = Dictionary(ps.map { ($0.device, $0.actions) }, uniquingKeysWith: { a, _ in a })
        offers = Dictionary(ps.compactMap { p in p.adminKey.map { (p.device, $0) } }, uniquingKeysWith: { a, _ in a })
        keyStores = Dictionary(ps.compactMap { p in p.keyStore.isEmpty ? nil : (p.device, p.keyStore) }, uniquingKeysWith: { a, _ in a })
    }

    /// Hands records this phone's root or admin key signed to the member,
    /// which keeps them and sends them to every peer.
    private func sendRecords(_ rs: [Member.Record]) {
        do {
            try node?.addRecords(rs)
        } catch {
            keysLog.error("handing the member records: \(String(reflecting: error), privacy: .public)")
        }
    }

    /// Takes in the records the member got from its peers.
    /// The group's records count as synced with a member once one has
    /// stayed connected for 30 s (its records came in at the connection's
    /// start): that spends the push hints-only marks from before which the
    /// records contradict.
    private func syncedSoon() {
        let before = Set(((try? node?.peers()) ?? []).map(\.device))
        guard !before.isEmpty else { return }
        let since = Date()
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(30))
            guard let self, let node = self.node else { return }
            let now = Set(((try? node.peers()) ?? []).map(\.device))
            let stayed = now.intersection(before)
            if !stayed.isEmpty { PushSetup.shared.synced(at: since, peers: stayed, recordsAt: self.recordsTakenAt) }
        }
    }

    /// When the app last took in records from the member that it did not
    /// have: a push hints-only mark is spent by a sync only after it.
    private var recordsTakenAt: Date?

    private func pullRecords() {
        guard let node, let rs = try? node.records(), !rs.isEmpty, let g = state else { return }
        var set = g.records
        guard !set.addAll(rs, groupCA: g.groupCA).isEmpty else { return }
        recordsTakenAt = Date()
        adopt(set)
    }

    // MARK: Keys

    private func key(label: String, secureEnclave: Bool) throws -> SecKey {
        if let k = try KeychainIdentity.loadKey(label: label) { return k }
        return try KeychainIdentity.makeKey(label: label, secureEnclave: secureEnclave)
    }

    /// The signer of this phone's root or admin key for an action the user
    /// asked for. In the Secure Enclave the key signs only after Face ID,
    /// Touch ID or the passcode: asked once, and good for the signatures of
    /// the next few minutes. A key made before the app asked is asked for
    /// too. A phone that is no admin has no such key.
    private func caSigner(reason: String) async throws -> SecKeySigner {
        guard isAdmin else { throw Failure.notAdmin }
        return try await signer(label: Self.signingLabel(state), reason: reason)
    }

    /// The signer of the key under label, after Face ID as caSigner asks.
    private func signer(label: String, reason: String) async throws -> SecKeySigner {
        guard Self.secureEnclave else { return try SecKeySigner(key(label: label, secureEnclave: false)) }
        let context: LAContext
        if let c = authorization.context() {
            context = c
        } else {
            context = LAContext()
            try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
            authorization.keep(context)
        }
        if try KeychainIdentity.loadKey(label: label) == nil {
            _ = try KeychainIdentity.makeKey(label: label, secureEnclave: true, userPresence: true)
        }
        guard let k = try KeychainIdentity.loadKey(label: label, context: context) else { throw KeychainIdentity.Failure.noIdentity }
        return try SecKeySigner(k)
    }

    func prepare() throws {
        _ = try memberSigner()
    }

    /// This phone's admin key, made now if it has none: in the Secure
    /// Enclave behind Face ID like the root key. Making it asks nothing;
    /// only a signature does.
    private func adminKey() throws -> SecKeySigner {
        let se = Self.secureEnclave
        return try SecKeySigner(KeychainIdentity.loadKey(label: Self.adminLabel)
            ?? KeychainIdentity.makeKey(label: Self.adminLabel, secureEnclave: se, userPresence: se))
    }

    /// The admin key a member phone's hellos offer, for the root's "Make it
    /// an admin" (docs/protocol.md, section 10, "Admins"); none on the root and on an admin.
    private func offeredAdminKey(_ g: PhoneGroup) -> Data? {
        guard !g.isAdmin else { return nil }
        do {
            return try adminKey().publicKeyDER
        } catch {
            keysLog.error("making the admin key to offer: \(String(reflecting: error), privacy: .public)")
            return nil
        }
    }

    /// Takes the admin CA the root sent when it made this member phone an
    /// admin: PhoneGroup.takeAdminCA checks it is for this phone's admin key
    /// and from the current root. The hellos offer the key no more, and
    /// sync starts again as an admin's.
    private func adminCAReceived(_ ca: Data, from: String) async {
        guard var g = state, !g.isAdmin, let key = offeredAdminKey(g) else { return }
        do {
            try g.takeAdminCA(ca, adminKey: key)
            try g.save(to: file)
        } catch {
            keysLog.error("the admin CA from \(from, privacy: .public): \(String(reflecting: error), privacy: .public)")
            return
        }
        state = g
        groupChanged()
        keysLog.notice("the root made this phone an admin")
        await restartSync()
    }

    private func memberSigner() throws -> SecKeySigner {
        try SecKeySigner(key(label: Self.memberLabel, secureEnclave: false))
    }

    private func identity(certificate: Data, _ member: SecKeySigner) throws -> SecIdentity {
        KeychainIdentity.removeCertificates(label: Self.memberLabel)
        return try KeychainIdentity.identity(certificate: certificate, key: member.key, label: Self.memberLabel, storeKey: false)
    }

    // MARK: Addresses

    /// The addresses to try, IPv4 first: a home network reaches those most
    /// surely, and each that fails costs its timeout.
    nonisolated static func ordered(_ addrs: [String]) -> [String] { JoinCode.ordered(addrs) }

    /// host and port of "host:port" or "[IPv6]:port".
    nonisolated static func split(_ addr: String) -> (String, UInt16)? { JoinCode.split(addr) }

    // MARK: Inviting from afar

    /// Opens a remote invitation through a hub of the group
    /// (docs/protocol.md, section 12, "Through the hub"): the core opens the
    /// guest tunnel on a connected hub and runs the pairing window here, the
    /// hub passing the pairing's bytes, for one device, for lifetime
    /// seconds. ask asks the user whether to admit a device that proved it
    /// knows the secret; on yes Face ID unlocks the group's key. ended gets
    /// the admitted device's name, or why the invitation ended without one.
    func invite(lifetime: Int, ask: @escaping @MainActor (PairingMember.Request) async -> Bool,
                ended: @escaping @MainActor (Result<String, Error>) -> Void) async throws -> AppModel.Invitation {
        guard let g = state, g.isAdmin else { throw Failure.notAdmin }
        guard let node else { throw CoreMember.Failure.notConnected }
        let unlocked = UnlockedSigner()
        // The key's public half needs no Face ID; its signature does.
        guard let k = try KeychainIdentity.loadKey(label: Self.signingLabel(g)) else { throw Failure.notAdmin }
        let publicKey = try SecKeySigner(k).publicKeyDER
        let adminCA = g.adminCA
        let inviting = try await Task.detached(priority: .userInitiated) {
            try CorePairing.Inviting(member: node, publicKey: publicKey, adminCA: adminCA, expires: lifetime) { digest in
                guard let s = unlocked.signer else { throw Failure.notAdmin }
                return try s.signature(digest: digest)
            }
        }.value
        let reason = String(localized: "Add a computer to your group", bundle: .app)
        Task.detached { [weak self] in
            var version: UInt64 = 0
            while true {
                guard let st = try? inviting.next(after: version) else { break }
                guard st.version != version else { continue }
                version = st.version
                switch st.state {
                case "joining":
                    guard let r = st.request else { continue }
                    let req = PairingMember.Request(device: r.device, info: Pairing.Info(name: r.name, os: r.os), fingerprint: r.fingerprint)
                    let yes = await self?.confirmInvited(req, ask: ask, reason: reason, unlocked: unlocked) ?? false
                    inviting.answer(yes)
                case "done":
                    inviting.close()
                    await MainActor.run { ended(.success(st.name)) }
                    return
                case "failed":
                    inviting.close()
                    let e: Error = st.failure ?? CorePairing.Failure("the invitation ended")
                    await MainActor.run { ended(.failure(e)) }
                    return
                default:
                    continue
                }
            }
        }
        let expires = Date().addingTimeInterval(TimeInterval(inviting.expires))
        return AppModel.Invitation(text: inviting.text, expires: expires, cancel: { Task.detached { inviting.close() } })
    }

    /// Asks the user about a device that used the invitation and, on yes,
    /// unlocks the key with Face ID for its certificate.
    private func confirmInvited(_ req: PairingMember.Request, ask: @MainActor (PairingMember.Request) async -> Bool, reason: String,
                                unlocked: UnlockedSigner) async -> Bool {
        guard await ask(req), let ca = try? await caSigner(reason: reason) else { return false }
        unlocked.signer = ca
        return true
    }

    /// The group's key once Face ID unlocked it, after the user said yes.
    private final class UnlockedSigner: CertificateSigner, @unchecked Sendable {
        var signer: SecKeySigner?
        var publicKeyDER: Data { signer?.publicKeyDER ?? Data() }
        func signature(for data: Data) throws -> Data {
            guard let signer else { throw Failure.notAdmin }
            return try signer.signature(for: data)
        }
    }

    // MARK: Joining

    /// Joins a group of 0.6 from afar by a remote invitation's text
    /// (docs/protocol.md, section 12): this phone dials the hub through the
    /// invitation's guest tunnel and shows its fingerprint (shown) for the
    /// inviting admin to compare; once admitted, the member starts on the
    /// group it keeps and reaches the hub through that tunnel until the
    /// hub's offer comes.
    func joinByInvite(_ text: String, shown: @escaping @MainActor (String) -> Void) async throws {
        guard state == nil else { return }
        let member = try memberSigner()
        try FileManager.default.createDirectory(at: memberDir, withIntermediateDirectories: true)
        let j = try CorePairing.Joiner(dir: memberDir, qr: "", invite: text, name: PhoneGroup.validName(UIDevice.current.name),
                                       os: "ios", publicKey: member.publicKeyDER) { try member.signature(digest: $0) }
        shown(j.fingerprint)
        try await follow(j, invite: true)
    }

    /// Joins a computer's group (docs/protocol.md, section 6, "A phone joins
    /// a computer's group"): finds the pairing window that `cbb pair` opened
    /// on the group's root by Bonjour (`p=1`), dials it and takes code, which
    /// the user typed from the computer's screen. Browsing waits up to 10 s
    /// for a window, then 2 s more for a second one, as the computers'
    /// joiner does: two windows at once and it refuses, rather than try the
    /// code on the wrong one. The root makes this phone an admin with the
    /// admin key it offers.
    func joinComputer(code: String) async throws {
        guard state == nil else { return }
        guard !LocalAddresses.current().isEmpty else { throw Failure.noNetwork }
        let window = try await findWindow()
        let member = try memberSigner()
        let admin = try adminKey()
        let cert = try GroupCertificates.selfSigned(device: Member.newID(), signer: member)
        let id = try identity(certificate: cert, member)
        let info = Pairing.Info(name: PhoneGroup.validName(UIDevice.current.name), os: "ios", adminKey: admin.publicKeyDER,
                                seal: Self.sealKey())
        // The window's certificate is checked by the code's exchange, not here.
        let t = TLSTransport(endpoint: window, alpn: Pairing.alpn, identity: id) { _ in true }
        let file = file
        let joined: PairingJoiner.Joined
        do {
            joined = try await withTaskCancellationHandler {
                try await t.start()
                defer { t.close() }
                guard let leaf = t.peerCertificate, let sid = t.exportKeyingMaterial(label: Pairing.exporterLabel, length: 32) else {
                    throw Failure.unreachable
                }
                let proved = try info.proving(sessionID: sid, with: admin)
                return try await PairingJoiner.join(over: t, code: code, info: proved, memberCert: leaf, joinerCert: cert,
                                                    sessionID: sid, now: Date()) { try PhoneGroup.joined($0).save(to: file) }
            } onCancel: {
                t.close()
            }
        } catch let e as PairingJoiner.Spent {
            // An admin computer that is not the root refuses a phone.
            if case .refused(.refused)? = e.underlying as? PairingJoiner.Failure { throw Failure.needsRoot }
            throw e
        }
        try modeBox.newDevice()
        forgetCredentials()
        state = PhoneGroup.joined(joined)
        try startSync()
    }

    /// The endpoint of the one computer announcing a pairing window; see
    /// joinComputer.
    private func findWindow() async throws -> NWEndpoint {
        let windows = OSAllocatedUnfairLock<Set<String>>(initialState: [])
        let b = BonjourBrowser { found in windows.withLock { $0 = Set(found.filter(\.pairing).map(\.device)) } }
        b.start()
        defer { b.stop() }
        let deadline = Date().addingTimeInterval(Self.browseFor)
        while windows.withLock({ $0.isEmpty }) {
            guard Date() < deadline else { throw Failure.noWindow }
            try await Task.sleep(for: .milliseconds(100))
        }
        try await Task.sleep(for: .seconds(Self.pairingSettle))
        let found = windows.withLock { $0 }
        guard found.count == 1 else { throw found.isEmpty ? Failure.noWindow : Failure.twoWindows }
        guard let endpoint = found.first.flatMap(b.endpoint(of:)) else { throw Failure.noWindow }
        return endpoint
    }

    /// The QR code text of the one home window Bonjour finds (p=1 with its
    /// ID and key hash), with the six digits the person typed from its
    /// screen. The app browses itself: the core's own mDNS would need the
    /// multicast entitlement.
    private func findHomeWindow(digits: String) async throws -> String {
        let windows = OSAllocatedUnfairLock<Set<FoundMember>>(initialState: [])
        let b = BonjourBrowser { found in
            windows.withLock { $0 = found.filter { $0.pairing && $0.windowID != nil && $0.fingerprint != nil } }
        }
        b.start()
        defer { b.stop() }
        let deadline = Date().addingTimeInterval(Self.browseFor)
        while windows.withLock({ $0.isEmpty }) {
            guard Date() < deadline else { throw Failure.noWindow }
            try await Task.sleep(for: .milliseconds(100))
        }
        try await Task.sleep(for: .seconds(Self.pairingSettle))
        let found = windows.withLock { $0 }
        guard found.count == 1, let w = found.first, let id = w.windowID, let fp = w.fingerprint else {
            throw found.isEmpty ? Failure.noWindow : Failure.twoWindows
        }
        guard let address = await b.addresses(of: w.device).first else { throw Failure.noWindow }
        return Discovery.windowLink(address: address, fingerprint: fp, id: id, digits: digits.filter { $0.isASCII && $0.isNumber })
    }

    // MARK: Removing

    /// Removes a device from the group: a revocation signed with this
    /// phone's root or admin key, sent to every connected computer, which
    /// refuse the device from then on. The phone stops dialing it.
    func remove(_ id: String) async throws {
        guard let current = state else { return }
        if !current.isRoot, id == current.records.rootDevice {
            try await takeOver(from: id)
            return
        }
        let ca = try await caSigner(reason: String(localized: "Remove a device from your group", bundle: .app))
        guard var g = state else { return }
        let r = try g.revoke(device: id, caSigner: ca, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        sendRecords([r])
        try? node?.disconnect(id)
    }

    /// Whether the group removed this phone: its records, once it has
    /// some, no longer list it. The app then offers to leave.
    var removed: Bool {
        guard let g = state, !g.records.records.isEmpty else { return false }
        return !g.devices.contains { $0.id == g.device }
    }

    /// Takes this phone out of its group (D-83, docs/design.md, "Leaving
    /// the group"): it stops syncing and deletes its keys, the group's
    /// files and the tunnel's settings; the sync mode stays. The phone can
    /// then make a group or join one again. The root leaves only when the
    /// group has no other devices than itself and its watch: nobody could
    /// add or remove one after it. The group keeps listing the phone
    /// until an admin removes it.
    func leave() async throws {
        guard let g = state else { throw Failure.noGroup }
        if g.isRoot {
            let others = g.devices.filter { $0.id != g.device && $0.role != "watch" }.map(\.name)
            if !others.isEmpty { throw Failure.rootLeaves(others) }
        }
        await hubDone()
        stopHome()
        stopNode()
        credentialBox = nil
        forgetCredentials()
        for label in [Self.caLabel, Self.adminLabel, Self.memberLabel] {
            KeychainIdentity.removeKey(label: label)
            KeychainIdentity.removePublicKeys(label: label)
            KeychainIdentity.removeCertificates(label: label)
        }
        SealKey.remove()
        let dir = file.deletingLastPathComponent()
        entries.remove()
        for url in [file, credentialsURL, dir.appendingPathComponent("attest-status"), memberDir] {
            try? FileManager.default.removeItem(at: url)
        }
        (online, offers, keyStores, infos, modes, actions, mutes) = ([], [:], [:], [:], [:], [:], [:])
        authorization.end()
        state = nil
        keysLog.notice("this phone left its group: its keys and the group's files are deleted")
    }

    /// Ends a conflict or cancels a claim (docs/protocol.md, section 10,
    /// "Stopping the exchange"): a resolve of the records ids, signed with
    /// the root key after Face ID and sent to every connected member.
    func resolve(_ ids: [Data]) async throws {
        guard state?.isRoot == true else { throw PhoneGroup.Failure.notRoot }
        let root = try await caSigner(reason: String(localized: "Resolve a conflict in your group", bundle: .app))
        guard var g = state else { throw PhoneGroup.Failure.notRoot }
        let r = try g.resolve(ids, rootSigner: root, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        sendRecords([r])
    }

    /// Unfreezes an admin computer that another admin froze
    /// (docs/protocol.md, section 10, "Removals and freezes keep what the author saw"): a thaw record signed with this
    /// phone's root or admin key, after Face ID, sent to every connected
    /// computer.
    func unfreeze(_ id: String) async throws {
        let ca = try await caSigner(reason: String(localized: "Unfreeze an admin computer", bundle: .app))
        guard var g = state else { return }
        let r = try g.thaw(device: id, caSigner: ca, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        sendRecords([r])
    }

    /// Gives a device another name (docs/protocol.md, section 10): a device
    /// record like its newest one with that name, signed with this phone's
    /// root or admin key after Face ID, sent to every connected computer.
    /// On the root, records what the attestation an Android phone sent
    /// shows (docs/protocol.md, section 17, "Evidence"), as renewals are
    /// made: only while the context of the user's last Face ID check lasts;
    /// the phone sends it again on its next connection.
    private func evidenceReceived(from peer: String?, chain: [Data], _ e: Member.Evidence) async {
        guard let peer, state?.isRoot == true else { return }
        await attestStatus.refreshIfDue()
        let revoked = await attestStatus.revoked
        guard var g = state, g.isRoot, let signer = renewer?.signer() else { return }
        do {
            guard let r = try g.evidence(device: peer, chain: chain, e, rootSigner: signer, now: Date(), revoked: revoked) else { return }
            try g.save(to: file)
            state = g
            groupChanged()
            sendRecords([r])
            keysLog.info("recorded what the attestation of \(peer, privacy: .public) shows")
        } catch {
            keysLog.error("the attestation of \(peer, privacy: .public): \(String(reflecting: error), privacy: .public)")
        }
    }

    func rename(_ id: String, to name: String) async throws {
        guard state?.isAdmin == true else { throw PhoneGroup.Failure.notAdmin }
        let ca = try await caSigner(reason: String(localized: "Rename a device", bundle: .app))
        guard var g = state else { return }
        let r = try g.rename(device: id, to: name, caSigner: ca, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        sendRecords([r])
    }

    /// Sets the sync mode of a connected computer (docs/protocol.md, section
    /// 15): a command signed with this phone's root or admin key after Face
    /// ID, which only that computer takes, within 30 s.
    func setMode(_ id: String, to mode: String) async throws {
        if id == state?.device {
            try modeBox.set(mode)
            try? node?.setSync(on: mode != "own")
            return
        }
        guard let node else { throw CoreMember.Failure.notConnected }
        let ca = try await caSigner(reason: String(localized: "Change a computer's sync mode", bundle: .app))
        guard let g = state else { return }
        let c = try g.modeCommand(to: id, mode: mode, caSigner: ca, now: Date())
        let r = try await node.command(c)
        if !r.done { throw CommandRefused(reason: r.reason ?? r.status) }
    }

    /// Turns sync on this phone on, or off for forMS milliseconds, 0 for
    /// until turned on again (design.md, "Sync on and off"): off, the
    /// clipboard is this phone's own, both ways. Needs no rights.
    func setSync(_ on: Bool, forMS: Int64) throws {
        try modeBox.setSync(on: on, untilMS: !on && forMS > 0 ? Int64(Date().timeIntervalSince1970 * 1000) + forMS : 0)
        try? node?.setSync(on: on, forMS: on ? 0 : forMS)
        groupChanged()
    }

    /// Mutes a device for the whole group for forMS milliseconds, 0 for
    /// until an admin unmutes it, or with on false ends its mute: a command
    /// signed with this phone's root or admin key after Face ID, passed on
    /// by a hub when this phone is not connected to it. This phone's own
    /// mute changes at once.
    func setMuted(_ id: String, _ on: Bool, forMS: Int64 = 0) async throws {
        guard state?.isAdmin == true else { throw PhoneGroup.Failure.notAdmin }
        if id == state?.device {
            try modeBox.setMute(on ? (forMS > 0 ? Int64(Date().timeIntervalSince1970 * 1000) + forMS : 0) : nil)
            try? node?.setMute(untilMS: modeBox.mutedUntilMS)
            return
        }
        guard let node else { throw CoreMember.Failure.notConnected }
        let ca = try await caSigner(reason: on ? String(localized: "Mute a device", bundle: .app) : String(localized: "Unmute a device", bundle: .app))
        guard let g = state else { return }
        let c = on ? try g.muteCommand(to: id, forMS: forMS, caSigner: ca, now: Date()) : try g.unmuteCommand(to: id, caSigner: ca, now: Date())
        let r = try await node.command(c)
        if !r.done { throw CommandRefused(reason: r.reason ?? r.status) }
    }

    /// Puts text where the focus of a computer is (design.md, "Remote
    /// paste"): a paste command signed with this phone's root or admin key
    /// after Face ID, passed on by a hub of the group connected to it when this phone
    /// is not; the computer answers once the text is in, or why not.
    func paste(_ id: String, text: String, method: String, enter: Bool, secret: Bool) async throws {
        guard let node else { throw CoreMember.Failure.notConnected }
        let ca = try await caSigner(reason: String(localized: "Paste on a device", bundle: .app))
        guard let g = state else { return }
        let c = try g.pasteCommand(to: id, text: text, method: method, enter: enter, secret: secret, caSigner: ca, now: Date())
        // The computer waits 5 s for its target, and 5 ms more for each typed byte.
        let wait = 10 + (method == "type" ? Double(text.utf8.count) * 0.005 : 0)
        let r = try await node.command(c, timeout: .milliseconds(Int64(wait * 1000)))
        if !r.done { throw CommandRefused(reason: r.reason ?? r.status) }
    }

    /// Pastes a picture or files where a computer's focus is
    /// (docs/protocol.md, section 15): they go to the group as a copy, then
    /// a paste command of kind media names that copy; the computer fetches
    /// it, puts it in its clipboard and presses the paste keys.
    func pasteMedia(_ id: String, parts: [CoreMember.Part], enter: Bool) async throws {
        guard let node else { throw CoreMember.Failure.notConnected }
        let ca = try await caSigner(reason: String(localized: "Paste on a device", bundle: .app))
        guard let g = state else { return }
        let copy = try node.copyMedia(parts)
        let c = try g.pasteCopyCommand(to: id, copyID: copy.id, enter: enter, caSigner: ca, now: Date())
        // The computer waits up to 20 s for the copy, then 8 s for its desktop.
        let r = try await node.command(c, timeout: .seconds(35))
        if !r.done { throw CommandRefused(reason: r.reason ?? r.status) }
    }

    /// Runs a quick action on a device (docs/protocol.md, section 15): an
    /// action command, signed with this phone's root or admin key after Face
    /// ID, names it; the device defines what it does and runs it only when
    /// its user turned it on there.
    func runAction(_ id: String, name: String) async throws {
        guard let node else { throw CoreMember.Failure.notConnected }
        let ca = try await caSigner(reason: String(localized: "Run a quick action", bundle: .app))
        guard let g = state else { return }
        let c = try g.actionCommand(to: id, name: name, caSigner: ca, now: Date())
        // A preset may take 20 s to start, and an own action runs up to 15 s.
        let r = try await node.command(c, timeout: .seconds(25))
        if !r.done { throw CommandRefused(reason: r.reason ?? r.status) }
    }

    /// Turns every quick action off on a device; only its user turns them
    /// on again.
    func actionsOff(_ id: String) async throws {
        guard let node else { throw CoreMember.Failure.notConnected }
        let ca = try await caSigner(reason: String(localized: "Run a quick action", bundle: .app))
        guard let g = state else { return }
        let c = try g.actionsOffCommand(to: id, caSigner: ca, now: Date())
        let r = try await node.command(c)
        if !r.done { throw CommandRefused(reason: r.reason ?? r.status) }
    }

    /// Makes a phone or a computer an admin (docs/protocol.md, section 10,
    /// "Admins"): the root key, after Face ID, certifies
    /// the admin key the device offers; the device gets its admin CA and
    /// every member the new record.
    func makeAdmin(_ id: String) async throws {
        // The dialog before it warned when the computer's keys sit in a file.
        try await makeAdmin(id, allowFileKey: true)
    }

    /// Makes the watch's key an admin key with the role watch (docs/protocol.md,
    /// section 10, "Watches"): the root key, after Face ID, issues its admin CA
    /// and signs its device record, which every member gets.
    func addWatch(_ request: WatchState.KeyRequest) async throws -> WatchState.Admission {
        guard state?.isRoot == true else { throw PhoneGroup.Failure.notRoot }
        let root = try await caSigner(reason: String(localized: "Make the watch an admin", bundle: .app))
        guard var g = state else { throw PhoneGroup.Failure.notRoot }
        let (ca, r) = try g.addWatch(device: request.device, name: request.name, os: "watchos", adminKey: request.key,
                                     rootSigner: root, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        sendRecords([r])
        return WatchState.Admission(device: request.device, adminCA: ca, group: g.tag)
    }

    func watchActions(for id: String) -> [String] {
        state?.watchActions(for: id).map(\.rawValue) ?? []
    }

    /// The body the watch signs (docs/protocol.md, section 10, "Watches"): any
    /// phone of the group builds it, since what counts is the watch's
    /// signature.
    func watchBody(_ ask: WatchState.Ask) throws -> Data {
        guard let g = state, let action = PhoneGroup.WatchAction(rawValue: ask.action) else { throw PhoneGroup.Failure.notForWatch }
        return try g.watchBody(action, device: ask.device, name: ask.name, watch: ask.watch, now: Date())
    }

    /// Brings what the watch signed into the group: a freeze or a removal
    /// joins the records and goes to every member now or at the next sync, a
    /// command goes to its device, which must be connected.
    func deliverFromWatch(_ signed: WatchState.Signed) async throws {
        let r = PhoneGroup.watchRecord(body: signed.body, signature: signed.signature, watchCA: signed.adminCA)
        let o = try JSONSerialization.jsonObject(with: signed.body) as? [String: Any]
        let type = o?["type"] as? String
        if type == "freeze" || type == "revoke" {
            guard var g = state else { throw PhoneGroup.Failure.notAWatch }
            guard g.add([r]).count == 1 else { throw CommandRefused(reason: "the group did not take the watch's record") }
            try g.save(to: file)
            state = g
            groupChanged()
            sendRecords([r])
            return
        }
        guard let to = o?["to"] as? String else { throw PhoneGroup.Failure.notForWatch }
        guard let node else { throw CoreMember.Failure.notConnected }
        _ = to
        let res = try await node.command(r, timeout: .seconds(25))
        if !res.done { throw CommandRefused(reason: res.reason ?? res.status) }
    }

    /// Makes a phone or a computer an admin; a computer whose keys sit in a
    /// file only with allowFileKey, else PhoneGroup.Failure.fileKey; a
    /// rootless install never (PhoneGroup.Failure.rootless). A phone keeps
    /// the store its record names.
    private func makeAdmin(_ id: String, allowFileKey: Bool) async throws {
        guard state?.isRoot == true, let key = offers[id] else { throw Failure.notAdmin }
        let phone = state?.devices.first { $0.id == id }?.role == "phone"
        let store = phone ? nil : keyStores[id]
        if !phone {
            guard Records.store(store, role: "member") != Records.rootless else { throw PhoneGroup.Failure.rootless }
            guard Records.store(store, role: "member") == Records.hardware || allowFileKey else { throw PhoneGroup.Failure.fileKey }
        }
        let root = try await caSigner(reason: String(localized: "Make a device an admin", bundle: .app))
        // The user's consent to a key in a file, after the dialog's
        // warning, lets the group take keys in files too.
        if !phone, Records.store(store, role: "member") == Records.file, allowFileKey, state?.keyLevel != Records.levelFiles {
            try rootRecord(root) { n, p, s in try n.setKeyLevel(Records.levelFiles, public: p, sign: s) }
        }
        guard var g = state else { return }
        let (ca, r) = try g.makeAdmin(device: id, adminKey: key, rootSigner: root, now: Date(), keyStore: store, allowFileKey: allowFileKey)
        try g.save(to: file)
        state = g
        groupChanged()
        sendRecords([r])
        _ = try? node?.sendAdminCA(to: id, ca: ca)
    }

    /// Removes the phone that holds the group's root, when it is lost: this
    /// admin phone makes a new root key in the Secure Enclave, behind Face
    /// ID, and its member in the Rust core makes the new root's CA and
    /// claims the group for it with the admin key (docs/protocol.md, section
    /// 10, "Handing the group over"). The claim waits the group's delay, in
    /// which the root, if it is still in use, cancels it;
    /// finishTakeOverIfDue then makes this phone the root.
    private func takeOver(from id: String) async throws {
        guard let n = node else { throw Failure.unreachable }
        try state?.checkTakeOver(from: id)
        let reason = String(localized: "Take the group over from the lost phone", bundle: .app)
        let admin = try await signer(label: Self.adminLabel, reason: reason)
        let root = try await newRootKey(reason: reason)
        guard var g = state, let ca = g.adminCA else { return }
        let newRoot = try n.rootCA(public: root.publicKeyDER) { try root.signature(digest: $0) }
        try n.claim(.takeOver, rootCA: newRoot, public: admin.publicKeyDER, ca: ca, sign: { try admin.signature(digest: $0) }, lost: id)
        g.claimed(newRoot: newRoot, lost: id)
        try keepTakeover(&g, n)
    }

    /// Takes the group the root handed to this phone (`cbb handover`,
    /// docs/protocol.md, section 10, "Handing the group over"): makes a new
    /// root key, and the member claims the group with this phone's admin
    /// key; the claim takes effect at once, so this phone becomes the root
    /// right after. The computer that was the root stays in the group.
    func takeHandedGroup() async throws {
        guard let n = node else { throw Failure.unreachable }
        try state?.checkHandedOver()
        let reason = String(localized: "Take the group the computer handed to this phone", bundle: .app)
        let admin = try await signer(label: Self.adminLabel, reason: reason)
        let root = try await newRootKey(reason: reason)
        guard var g = state, let ca = g.adminCA else { return }
        let newRoot = try n.rootCA(public: root.publicKeyDER) { try root.signature(digest: $0) }
        try n.claim(.takeHandedOver, rootCA: newRoot, public: admin.publicKeyDER, ca: ca, sign: { try admin.signature(digest: $0) })
        g.claimed(newRoot: newRoot, lost: nil)
        try keepTakeover(&g, n)
        await finishTakeOverIfDue()
    }

    /// A new root key in the Secure Enclave, behind Face ID, for a claim;
    /// a root key left from a group this phone made before goes.
    private func newRootKey(reason: String) async throws -> SecKeySigner {
        KeychainIdentity.removeKey(label: Self.caLabel)
        let se = Self.secureEnclave
        _ = try KeychainIdentity.makeKey(label: Self.caLabel, secureEnclave: se, userPresence: se)
        return try await signer(label: Self.caLabel, reason: reason)
    }

    /// Keeps g, this phone's group after a step of a takeover, with the
    /// records the member holds now, its claim or the new root's among them.
    private func keepTakeover(_ g: inout PhoneGroup, _ n: CoreMember) throws {
        g.add(try n.records())
        try g.save(to: file)
        state = g
        groupChanged()
    }

    /// What the member's signing callback answers while a claim waits: it
    /// asks for no signature then.
    private struct ClaimWaits: Error {}

    /// Makes this phone the group's root once its claim took effect: the
    /// core's member signs, with the new root key, this phone's certificate
    /// from the new root and what a new root starts with (docs/design.md,
    /// "Losing the phone"). The member says where the claim stands without Face ID,
    /// since it signs nothing while the claim waits; a claim that was
    /// cancelled or became void is dropped, one that still waits stays.
    private func finishTakeOverIfDue() async {
        guard let n = node, let g = state, let claim = g.claim else { return }
        let lost = g.claimedFrom
        do {
            guard let k = try KeychainIdentity.loadKey(label: Self.caLabel) else { throw KeychainIdentity.Failure.noIdentity }
            let rootKey = try SecKeySigner(k).publicKeyDER
            let name = PhoneGroup.validName(UIDevice.current.name), seal = Self.sealKey()
            func ask(_ sign: @escaping (Data) throws -> Data) throws -> CoreMember.Takeover {
                try n.finishTakeover(rootCA: claim, public: rootKey, name: name, store: Records.hardware, seal: seal, sign: sign)
            }
            var t = try ask { _ in throw ClaimWaits() }
            switch t.state {
            case "cancelled", "void":
                keysLog.notice("the claim to take the group over ended (\(t.state, privacy: .public)); this phone stays an admin")
                guard var g = state else { return }
                g.dropClaim()
                try keepTakeover(&g, n)
                return
            case "effective":
                break
            default:
                keysLog.info("the claim to take the group over is \(t.state, privacy: .public), \(t.leftMS) ms left")
                return
            }
            let root = try await signer(label: Self.caLabel, reason: String(localized: "Take the group over from the lost phone", bundle: .app))
            t = try ask { try root.signature(digest: $0) }
            guard let cert = t.cert, var g = state else { return }
            g.becameRoot(cert: cert, records: try n.records())
            try g.save(to: file)
            state = g
            groupChanged()
            if let lost { try? n.disconnect(lost) }
            await restartSync()
        } catch {
            keysLog.error("finishing the takeover: \(String(describing: error), privacy: .public)")
        }
    }

    /// This phone's public key for sealed messages, which its pairing and
    /// device record carry so that commands for it come sealed (section
    /// 15); nil, with the reason in the log, when the keychain refuses it,
    /// and the commands for it then come in the open.
    nonisolated static func sealKey() -> Data? {
        do {
            return try SealKey.publicKey()
        } catch {
            keysLog.error("no key for sealed messages: \(String(describing: error), privacy: .public)")
            return nil
        }
    }

    // MARK: Server credentials

    /// credentials.json beside the group's file.
    private var credentialsURL: URL { file.deletingLastPathComponent().appendingPathComponent("credentials.json") }

    /// The newest signed entry points the computers sent (docs/protocol.md,
    /// section 16, "Entry points"), entries.json beside the group's file.
    private lazy var entries = EntriesFile(url: memberDir.appendingPathComponent("entries.json"),
                                           log: { hubLog.error("\($0, privacy: .public)") })

    /// Drops the credentials and the keys for the servers of an earlier
    /// group, when the phone makes or joins one.
    private func forgetCredentials() {
        try? FileManager.default.removeItem(at: credentialsURL)
        periodKeys.clear()
    }

    /// Brings the group's server credentials up to date as far as this
    /// phone can (docs/protocol.md, section 18) and sends what it signed to
    /// the computers: its server key for the period; on the root, the
    /// period when one is due, while the user's last Face ID lasts, and the
    /// hubs' and members' credentials; on a listed admin, the members'.
    private func refreshCredentials() {
        guard let box = credentialBox, let node, let member = try? memberSigner() else { return }
        let renewer = renewer
        let root: (() -> CertificateSigner?)? = state?.isRoot == true ? { renewer?.signer() } : nil
        let signed = box.refresh(member: member, keys: periodKeys, rootSigner: root)
        if !signed.isEmpty { _ = try? node.sendCredentials(signed) }
    }

    /// Passes a changed group to the parts that run with it.
    private func groupChanged() {
        guard let g = state else { return }
        recordBox?.replace(g.records)
        credentialBox?.group = g
        refreshCredentials()
        admins?.group = g
        relay?.allowed = Self.allowed(g)
        relay?.addresses = g.addresses
    }

    /// The devices the phone dials: those in the list. A phone that joined
    /// has no records until a computer sends them, so it dials every member
    /// of the group until then; TLS still checks each against the group CA.
    nonisolated static func allowed(_ g: PhoneGroup) -> Set<String>? {
        g.records.records.isEmpty ? nil : Set(g.devices.map(\.id))
    }

    /// Takes in records a computer sent, and the roots they lead to: a
    /// new root, after another admin phone took the group over, means
    /// connecting again with it trusted.
    private func adopt(_ set: RecordSet) {
        guard var g = state else { return }
        let roots = g.roots
        g.add(set.records)
        g.records.takeClaimTimes(set.claimTimes)
        guard g != state else { return }
        try? g.save(to: file)
        state = g
        recordBox?.replace(g.records)
        admins?.group = g
        relay?.allowed = Self.allowed(g)
        credentialBox?.group = g
        refreshCredentials()
        if g.roots != roots { Task { await restartSync() } }
    }

    // MARK: Syncing

    /// The folder where the phone's member in the core keeps the records,
    /// the entry points and the images and files, beside the group's file.
    private var memberDir: URL { file.deletingLastPathComponent().appendingPathComponent("member", isDirectory: true) }

    /// Starts the phone's member in the core and finding the computers,
    /// once there is a group.
    private func startSync() throws {
        guard let g = state, node == nil else { return }
        let signer = try memberSigner()
        try FileManager.default.createDirectory(at: memberDir, withIntermediateDirectories: true)
        Self.moveEntries(from: file.deletingLastPathComponent(), to: memberDir)
        let node = try CoreMember(.init(dir: memberDir, name: UIDevice.current.name, osVersion: Self.ownDevice.osVersion ?? "",
                                        version: Self.ownDevice.version ?? "", device: g.device, publicKeyDER: signer.publicKeyDER,
                                        seal: try SealKey.secret(), cert: g.memberCert, issuer: g.memberIssuer, groupCA: g.groupCA,
                                        roots: g.trusted, adminKey: offeredAdminKey(g))) { try signer.signature(digest: $0) }
        try node.addRecords(g.records.records)
        try node.setSync(on: modeBox.mode != "own", forMS: modeBox.syncOffUntilMS.map { max(1, $0 - Int64(Date().timeIntervalSince1970 * 1000)) } ?? 0)
        if let muted = modeBox.mutedUntilMS { try node.setMute(untilMS: muted) }
        let box = RecordBox(groupCA: g.groupCA, set: g.records)
        let credentials = CredentialBox(url: credentialsURL, group: g)
        credentials.onAdd = { [weak self] in Task { @MainActor in self?.refreshCredentials() } }
        // An admin phone renews the computers' certificates when they
        // connect and are due (docs/protocol.md, section 2).
        let renewer = Renewer(group: g, secureEnclave: Self.secureEnclave, authorization: authorization)
        // The root sends a computer it made an admin its admin CA again
        // when the computer still offers the key.
        let admins = AdminBox(group: g)
        // A phone in a group of 0.5 syncs at home only (D-123); on a group
        // of 0.6 the Live member runs sync away from home, the hub and the
        // relay itself (AwayOn06).
        let relay = Relay(group: g.tag, device: g.device)
        relay.allowed = Self.allowed(g)
        let browser = BonjourBrowser(log: { browseLog.notice("\($0, privacy: .public)") }) { found in relay.update(found) }
        relay.attach(node: node, browser: browser)
        // The computers at known addresses are dialed even while browsing finds nothing.
        relay.addresses = g.addresses
        browser.start()
        (self.node, self.browser, self.relay, recordBox, self.renewer, self.admins) = (node, browser, relay, box, renewer, admins)
        credentialBox = credentials
        let handler = Handler(node: node, box: box, renewer: renewer, admins: admins, credentials: credentials,
                              modeBox: modeBox, device: g.device)
        events = Task { @MainActor [weak self] in
            for await e in node.events {
                handler.handle(e)
                self?.handled(e)
            }
        }
        if background { try? node.pause() }
        refreshHub()
        refreshCredentials()
    }

    /// The entry points an earlier version kept beside the group's file go
    /// to the member's folder, where the core keeps them now.
    nonisolated static func moveEntries(from dir: URL, to memberDir: URL) {
        let old = dir.appendingPathComponent("entries.json"), new = memberDir.appendingPathComponent("entries.json")
        guard FileManager.default.fileExists(atPath: old.path) else { return }
        if !FileManager.default.fileExists(atPath: new.path) { try? FileManager.default.moveItem(at: old, to: new) }
        try? FileManager.default.removeItem(at: old)
    }

    /// What the member's events ask of the group, off the main actor's
    /// state: the parts that answer at once (renewals, admin CAs,
    /// credentials, commands for this phone).
    final class Handler: @unchecked Sendable {
        let node: CoreMember
        let box: RecordBox
        let renewer: Renewer
        let admins: AdminBox
        let credentials: CredentialBox
        let modeBox: ModeBox
        let device: String

        init(node: CoreMember, box: RecordBox, renewer: Renewer, admins: AdminBox, credentials: CredentialBox,
             modeBox: ModeBox, device: String) {
            (self.node, self.box, self.renewer, self.admins) = (node, box, renewer, admins)
            (self.credentials, self.modeBox, self.device) = (credentials, modeBox, device)
        }

        func handle(_ e: CoreMember.Event) {
            switch e {
            case let .peer(p):
                answer(p)
            case let .message(from, .credentials(cs)):
                guard !cs.isEmpty, cs.count <= ServerCredentials.maxCredentials else { return }
                let fresh = credentials.add(cs)
                // New ones go on to the others, not back to the sender.
                if !fresh.isEmpty { _ = try? node.sendCredentials(fresh, except: from) }
            case let .caller(token, _, _):
                // A phone in a group of 0.5 takes no relay's calls (D-123).
                try? node.caller(token, device: nil)
            case let .command(token, from, c):
                command(token, from: from, c)
            default:
                break
            }
        }

        /// Answers a peer's hello: renews its certificate when it is due and
        /// sends a computer this root made an admin its admin CA again.
        private func answer(_ p: CoreMember.Peer) {
            guard !p.recordsOnly else { return }
            if !p.chain.isEmpty, let renewed = renewer.renew(p.chain) {
                _ = try? node.sendCert(to: p.device, cert: renewed.cert, issuer: renewed.issuer)
            }
            if let key = p.adminKey, let ca = admins.group.computerAdminCA(for: key) {
                _ = try? node.sendAdminCA(to: p.device, ca: ca)
            }
            // The credentials kept go to this peer, after its hello.
            let all = credentials.all
            if !all.isEmpty { _ = try? node.sendCredentials(all, to: p.device) }
        }

        /// Carries out a command for this phone and answers it; what it
        /// changes beyond its result comes once the result has gone back.
        private func command(_ token: UInt64, from: String, _ c: Member.Record) {
            let (result, change) = modeBox.take(c, from: from, records: box, me: device)
            try? node.answer(token, result: result)
            switch change {
            case let .mode(mode)?: try? node.setSync(on: mode != "own")
            case .mute?:
                // Connects again once the result has gone back, so that the
                // hellos say whether it is muted.
                let (node, modeBox) = (node, modeBox)
                Task {
                    try? await Task.sleep(for: .milliseconds(500))
                    try? node.setMute(untilMS: modeBox.mutedUntilMS)
                }
            case .awayOff?: break // the app turns it off, on the main actor
            case nil: break
            }
        }
    }

    /// What the member's events change on the main actor: the copies that
    /// come in, the records and peers it shows, evidence, the log.
    private func handled(_ e: CoreMember.Event) {
        switch e {
        case let .copy(c):
            guard let node, let g = state, c.origin != g.device, Member.receives(modeBox.mode),
                  (try? node.waiting())?.id == c.id else { return }
            Task {
                do {
                    try await take(c)
                } catch {
                    imageLog.error("taking a copy: \(String(reflecting: error), privacy: .public)")
                }
            }
        case .peer:
            take(peers: (try? node?.peers()) ?? [])
            pullRecords()
            syncedSoon()
        case let .message(from, .admin(ca)):
            Task { await adminCAReceived(ca, from: from) }
        case let .message(from, .evidence(ev)):
            let chain = ((try? node?.peers()) ?? []).first { $0.device == from }?.chain ?? []
            guard !chain.isEmpty else { return }
            Task { await evidenceReceived(from: from, chain: chain, ev) }
        case let .command(_, _, c):
            // Sync away from home turned off by an admin, once the result has
            // gone back on the connection that brought the command.
            guard (try? JSONSerialization.jsonObject(with: c.body) as? [String: Any])?["type"] as? String == "away-off" else { return }
            Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(500))
                do { try await self.setAwayFromHome(false) } catch {
                    modeLog.error("cannot turn sync away from home off: \(String(reflecting: error), privacy: .public)")
                }
            }
        case let .mute(muted, forMS, by):
            // The member carried out an admin's mute or unmute; the phone
            // shows it.
            try? modeBox.setMute(muted ? (forMS > 0 ? Int64(Date().timeIntervalSince1970 * 1000) + forMS : 0) : nil)
            modeLog.notice("\(by, privacy: .public) \(muted ? "muted" : "unmuted", privacy: .public) this phone")
        case let .sync(off, by):
            // The member of 0.6 carried out an admin's sync mode and keeps
            // it; the phone shows it.
            do { try modeBox.setSync(on: !off) } catch {
                modeLog.error("cannot save the sync mode: \(String(reflecting: error), privacy: .public)")
            }
            modeLog.notice("\(by, privacy: .public) turned sync \(off ? "off" : "on", privacy: .public) on this phone")
        case let .log(line):
            syncLog.notice("\(line, privacy: .public)")
            recentLog.append(line)
            if recentLog.count > 300 { recentLog.removeFirst(recentLog.count - 300) }
        case let .panic(details):
            // A member that broke stops and starts again.
            syncLog.error("the member broke, starting it again: \(details, privacy: .public)")
            onPanic?(details, recentLog)
            Task { await restartSync() }
        case .identity:
            // The core kept the certificate an admin renewed for this phone;
            // the app renews its own (renewOwnCertificate) and keeps that.
            syncLog.notice("the member got a renewed certificate or a new root")
        case let .rootChanged(from, to, seq):
            // Every device shows it, and nobody turns it off.
            rootChanged = AppModel.RootChange(from: name(of: from), to: name(of: to), seq: seq)
            Task { await refresh() }
        case .state, .notice:
            Task { await refresh() }
        default:
            break
        }
    }

    /// Stops syncing and starts again, with a renewed certificate.
    private func restartSync() async {
        await hubDone()
        stopHome()
        stopNode()
        credentialBox = nil
        try? startSync()
    }

    /// Stops the member, its events and the browsing.
    private func stopNode() {
        events?.cancel()
        browser?.stop()
        node?.stop()
        (node, events, browser, relay, recordBox, renewer, admins) = (nil, nil, nil, nil, nil, nil, nil)
        publisher?.stop()
        (publisher, homePort) = (nil, nil)
    }

    // MARK: The phone as the hub

    /// The phone as the group's hub as Settings shows it: nil without a
    /// group, on a phone that is no admin, which cannot be the hub, and in
    /// a group of 0.5, where a phone is no hub (D-123). The forwarder is
    /// the one the group's root set.
    func hubStatus() async -> AppModel.Hub? {
        guard isV06, state?.isAdmin == true else { return nil }
        let a = awayState06, p = hub06, byRoot = rootForwarder06
        let (status, error) = AwayOn06.hubStatus(p, a, paused: !foreground, forwarder: byRoot != nil)
        var h = AppModel.Hub(on: p.on, status: status, error: error, forwarder: byRoot.map { .init(endpoint: $0.endpoint, pin: $0.key) },
                             home: p.isHome(network), clients: a?.clients ?? 0, disguise: p.hides)
        h.entriesStale = status == .failed && a?.forwarder?.entriesStale == true
        return h
    }

    /// Tells the group the app came to the front or went to the background;
    /// the hub follows.
    func setForeground(_ on: Bool) {
        foreground = on
        refreshHub()
        // Back at the front the member connects at once, and without a
        // computer browsing starts again too, as iOS may have ended it.
        guard on, let node else { return }
        background = false
        try? node.resume()
        if node.connected().isEmpty { browser?.restart() }
        if isV06 { Task { await renewPeriod06() } }
    }

    /// On the root phone of a group of 0.6, renews the group's server
    /// credentials with the root key when they are due, asking with Face ID
    /// first: only when the app comes to the front, and with the next root
    /// action (the member renews them with its key then), never at another
    /// moment.
    private func renewPeriod06() async {
        guard isRoot, let node, (try? node.periods())?.due == true else { return }
        do {
            let root = try await caSigner(reason: String(localized: "Renew the group's keys for sync away from home", bundle: .app))
            _ = try rootRecord(root) { n, p, s in try n.renewPeriod(public: p, sign: s) }
        } catch {
            relayLog.warning("renewing the group's server credentials; the next time the app opens asks again: \(String(describing: error), privacy: .public)")
        }
    }

    /// The app went to the background, or came back from it: there the
    /// member closes its connections with a goodbye and makes none, as iOS
    /// would end them anyway.
    func setBackground(_ on: Bool) {
        background = on
        // In the background the keys sign without asking no more: the
        // next signing action asks for Face ID again.
        if on { authorization.end() }
        guard let node else { return }
        if on { try? node.pause() } else { try? node.resume() }
    }

    /// One pass of the background refresh (BackgroundRefresh): the member
    /// connects while it runs, and in the background lets go again after.
    func backgroundPass(_ running: Bool) {
        guard let node, background else { return }
        if running { try? node.resume() } else { try? node.pause() }
    }

    /// Makes this phone the group's hub, or stops it being the hub, in a
    /// group of 0.6; the network it is on becomes a home network of the hub.
    func setPhoneHub(_ on: Bool) async throws {
        guard isV06, state?.isAdmin == true else { return }
        var p = hub06
        p.on = on
        if on { p = p.adding(home: network) }
        try saveHub06(p)
        if on { try updateHub06() } else { unhub06() }
    }

    /// Sets how the hub's tunnel hides.
    func setHubDisguise(_ d: HubOnPhone.Disguise) async throws {
        guard isV06, state?.isAdmin == true else { return }
        var p = hub06
        p.hides = d
        try saveHub06(p)
        try updateHub06()
    }

    /// Remembers the network the phone is on as a home network, where the
    /// hub takes members and publishes itself.
    func addHomeNetwork() async throws {
        guard isV06, state?.isAdmin == true, let network else { return }
        try saveHub06(hub06.adding(home: network))
        refreshHub()
    }

    /// Runs updateHub06 after the changes before it.
    private func refreshHub() {
        let previous = hubWork
        hubWork = Task { @MainActor [weak self] in
            await previous?.value
            guard let self, self.isV06 else { return }
            do { try self.updateHub06() } catch { hubLog.error("the hub did not start: \(String(reflecting: error), privacy: .public)") }
        }
    }

    // MARK: Away, the hub and the relay on 0.6

    private func saveHub06(_ p: AwayOn06.Prefs) throws {
        try Hub06Keychain.save(p)
        hub06 = p
    }

    /// On a group of 0.6, has the Live member serve as a hub while the
    /// user turned it on and the app is in front, publishing it on a home
    /// network of the hub. In the background the member pauses and the hub
    /// stays one, so that a short trip away hands no clients over: they
    /// wait out the gap as for any hub that goes quiet, and move on to the
    /// group's next hub after it. Only the switch stops the hub at once.
    private func updateHub06() throws {
        guard let node, let g = state, g.isAdmin, hub06.on else { return unhub06() }
        guard foreground else { return stopHome() }
        try AwayOn06.serve(node, hub06, homeAddrs: LocalAddresses.current().filter { !$0.contains(":") }, byRoot: try? node.rootForwarder())
        guard hub06.isHome(network) else { return stopHome() }
        guard homePort == nil else { return }
        for p in [Self.memberPort, 0] {
            guard let home = try? node.listen(.home, port: p) else { continue }
            homePort = home
            do {
                publisher = try BonjourPublisher(name: g.device, port: home, txt: ["v": "1", "g": g.tag, "r": "phone"])
            } catch {
                hubLog.error("the hub cannot publish itself on the home network: \(String(reflecting: error), privacy: .public)")
            }
            return
        }
        hubLog.error("the hub cannot listen on the home network")
    }

    /// On a group of 0.6, stops the Live member serving as a hub, when it does.
    private func unhub06() {
        stopHome()
        guard let node, (try? node.awayStatus())?.hub == true else { return }
        do { try node.stopHub() } catch { hubLog.error("the hub did not stop: \(String(reflecting: error), privacy: .public)") }
    }

    /// On a group of 0.6, sync away from home as the Live member runs it; nil while it is off.
    private var awayState06: CoreMember.AwayState? { try? node?.awayStatus() }

    /// On a group of 0.6, the forwarder the group's root set for this phone as a hub; nil while it set none.
    private var rootForwarder06: CoreMember.RootForwarder? { (try? node?.rootForwarder()) ?? nil }

    /// On a group of 0.6, sets the group's relay (docs/design.md, "Blind
    /// relay"), where every device meets the others while sync away from
    /// home is on: the root writes it into the group's settings, signed
    /// with the root key after Face ID. Both empty meet at no relay.
    private func setGroupRelay(address: String, pin: String) async throws {
        guard isRoot else { throw Failure.needsRoot }
        let relays: [String]
        if address.isEmpty && pin.isEmpty {
            relays = []
        } else {
            guard let ep = HubState.endpoint(address), !pin.isEmpty else { throw RelayOnPhone.Failure.badRelay }
            relays = ["\(ep) \(pin)"]
        }
        let root = try await caSigner(reason: String(localized: "Set the group's relay", bundle: .app))
        try rootRecord(root) { n, p, s in try n.setRelays(relays, public: p, sign: s) }
    }

    /// Why sync away from home of 0.6 does not get through, as the member says.
    struct Away06Failure: Error, CustomStringConvertible {
        let message: String
        var description: String { message }
    }

    private func hubDone() async { await hubWork?.value }

    private func stopHome() {
        publisher?.stop()
        publisher = nil
        if homePort != nil { try? node?.unlisten(.home) }
        homePort = nil
    }

    /// Why the phone does not sync (docs/apps.md, "Why it does not sync"),
    /// as the member says: the member of 0.6 runs the tunnel itself and
    /// says where it stands; a phone in a group of 0.5 syncs at home only.
    func why() async -> [WhyReason] {
        guard let node else { return [WhyReason(code: "not_in_group", level: "stop")] }
        return (try? node.why(away: nil)) ?? []
    }

    /// The blind relay as Settings shows it; nil without a group, and in a
    /// group of 0.5, where a phone meets no relay (D-123).
    func relayStatus() async -> AppModel.BlindRelay? {
        guard isV06, state != nil else { return nil }
        let a = awayState06
        let (status, error) = AwayOn06.relayStatus(a)
        var r = AppModel.BlindRelay(status: status, error: error, relay: a?.relay.flatMap { $0.endpoint.isEmpty ? nil : .init(endpoint: $0.endpoint, pin: "") },
                                    online: a?.relay?.online.count ?? 0)
        r.editable = isRoot
        r.periodOverdue = isRoot && ((try? node?.periods())?.overdue ?? false)
        return r
    }

    /// Sets the group's relay at address, whose key is pin, after the user
    /// read what a relay learns; both empty meet at no relay.
    func setRelay(address: String, pin: String) async throws {
        let a = address.trimmingCharacters(in: .whitespaces), p = pin.trimmingCharacters(in: .whitespaces)
        try await setGroupRelay(address: a, pin: p)
    }

    /// The member port the hub takes members on at home, as the computers';
    /// another when it is taken.
    static let memberPort: UInt16 = 8764

    /// Sync away from home as Settings shows it; nil without a group, and
    /// in a group of 0.5, where a phone syncs at home only (D-123).
    func awayStatus() async -> (on: Bool, status: AwayFromHome.Status, error: Error?, hub: String?, hubs: [String])? {
        guard isV06, let node else { return nil }
        let a = awayState06
        let connected = Set(node.connected())
        let status = AwayOn06.awayStatus(a) { connected.contains($0) }
        let error = a.flatMap { $0.error.isEmpty ? nil : Away06Failure(message: AwayOn06.reason($0.error, $0.detail)) }
        let hub = a.flatMap { $0.hubDevice.isEmpty || status == .connecting ? nil : $0.hubDevice }
        return (a?.isOn == true && a?.hub != true, status, error, hub, a.map { $0.hubDevice.isEmpty ? [] : [$0.hubDevice] } ?? [])
    }

    /// Turns sync away from home on or off, in a group of 0.6.
    func setAwayFromHome(_ on: Bool) async throws {
        guard isV06 else { return }
        guard let node else { throw Failure.noGroup }
        try node.setAway(on)
    }

    /// A value set after the closures that read it are made.
    final class Ref<T: AnyObject>: @unchecked Sendable {
        private let lock = NSLock()
        private var _value: T?
        var value: T? {
            get { lock.withLock { _value } }
            set { lock.withLock { _value = newValue } }
        }
    }

    /// The context of the user's last Face ID check and when it passed. It
    /// lets the keys sign for `lasts` seconds after the check, while the app
    /// stays at the front; after that, or on `end`, the context is
    /// invalidated, so no copy of it signs any more, and the next signing
    /// action asks again.
    final class Authorization: @unchecked Sendable {
        let lasts: TimeInterval
        private let now: () -> Date
        private let lock = NSLock()
        private var kept: (context: LAContext, at: Date)?

        init(lasts: TimeInterval, now: @escaping () -> Date = Date.init) { (self.lasts, self.now) = (lasts, now) }

        /// Keeps the context of a check that just passed.
        func keep(_ context: LAContext) {
            let old = lock.withLock { () -> LAContext? in
                defer { kept = (context, now()) }
                return kept?.context
            }
            if let old, old !== context { old.invalidate() }
        }

        /// The kept context while it lasts, or nil.
        func context() -> LAContext? {
            let (live, stale) = lock.withLock { () -> (LAContext?, LAContext?) in
                guard let k = kept else { return (nil, nil) }
                let age = now().timeIntervalSince(k.at)
                if age >= 0 && age < lasts { return (k.context, nil) }
                kept = nil
                return (nil, k.context)
            }
            stale?.invalidate()
            return live
        }

        /// Ends the window at once.
        func end() {
            let old = lock.withLock { () -> LAContext? in
                defer { kept = nil }
                return kept?.context
            }
            old?.invalidate()
        }
    }

    /// Issues renewed member certificates with the root or admin key, without
    /// asking: in the Secure Enclave only while the user's last Face ID
    /// check lasts (Authorization), so a computer that is due and connects
    /// after that gets its renewal on a later connection.
    final class Renewer: @unchecked Sendable {
        let group: PhoneGroup
        let secureEnclave: Bool
        let authorization: Authorization

        init(group: PhoneGroup, secureEnclave: Bool, authorization: Authorization) {
            (self.group, self.secureEnclave, self.authorization) = (group, secureEnclave, authorization)
        }

        /// A renewal for a peer's chain, leaf first, when it is due and this
        /// phone may renew it.
        func renew(_ chain: [Data]) -> PhoneGroup.Renewal? {
            guard group.isAdmin, let cert = chain.first,
                  GroupCertificates.isDue(cert, groupCA: group.adminCA ?? group.currentRoot, now: Date()),
                  let signer = signer() else { return nil }
            return group.renewal(chain: chain, caSigner: signer, now: Date())
        }

        /// The root or admin key's signer while it signs without asking.
        func signer() -> SecKeySigner? {
            var ctx = authorization.context()
            if secureEnclave && ctx == nil {
                let quiet = LAContext()
                quiet.interactionNotAllowed = true // a key that needs the user fails instead of asking
                ctx = quiet
            }
            guard let k = try? KeychainIdentity.loadKey(label: LiveGroup.signingLabel(group), context: ctx) else { return nil }
            return try? SecKeySigner(k)
        }
    }

    /// The group as the node's adminCA closure reads it, off the main actor.
    final class AdminBox: @unchecked Sendable {
        private let lock = NSLock()
        private var _group: PhoneGroup
        var group: PhoneGroup {
            get { lock.withLock { _group } }
            set { lock.withLock { _group = newValue } }
        }
        init(group: PhoneGroup) { _group = group }
    }

    /// The group's records for the node, which exchanges them with the
    /// computers.
    /// This phone's sync mode (docs/design.md, "Sync modes"), in the file
    /// mode beside the group's, as the computers keep it, own when there is
    /// none; and the replay cache of the commands
    /// it took (docs/protocol.md, section 15).
    final class ModeBox: @unchecked Sendable {
        private let lock = NSLock()
        private let url: URL
        private var commands: [String: Int64] = [:]
        /// When the app started: the replay cache starts empty, so a command
        /// signed before then may have been carried out already.
        private let startedMS = Int64(Date().timeIntervalSince1970 * 1000)
        /// The most command IDs it keeps; a command lives at most 30 s, as Go's maxCommandIDs.
        static let maxCommands = 4096

        init(url: URL) { self.url = url }

        /// The sync mode: shared (sync on) or own (sync off); own turned off
        /// for a time reads as shared once the time is over.
        var mode: String {
            lock.withLock {
                let m = (try? String(contentsOf: url, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
                let mode = m.flatMap { Member.modes.contains($0) ? $0 : nil } ?? "shared"
                if mode == "own", let until = readMute().sync, until > 0, until <= Int64(Date().timeIntervalSince1970 * 1000) {
                    return "shared"
                }
                return mode
            }
        }

        /// Sets the sync mode and keeps it.
        func set(_ mode: String) throws {
            guard Member.modes.contains(mode) else { throw Commands.Failure.unknownMode(mode) }
            try lock.withLock { try Data((mode + "\n").utf8).write(to: url, options: .atomic) }
        }

        /// An admin's mute of this phone and until when its user turned sync
        /// off, as Go's service keeps them in mute.json: until when in Unix
        /// milliseconds, 0 for until it is lifted or turned on.
        private struct MuteFile: Codable { var mute: Int64?, sync: Int64? }
        private var muteURL: URL { url.deletingLastPathComponent().appendingPathComponent("mute.json") }

        private func readMute() -> MuteFile {
            (try? Data(contentsOf: muteURL)).flatMap { try? JSONDecoder().decode(MuteFile.self, from: $0) } ?? MuteFile()
        }

        private func writeMute(_ change: (inout MuteFile) -> Void) throws {
            try lock.withLock {
                var m = readMute()
                change(&m)
                try JSONEncoder().encode(m).write(to: muteURL, options: .atomic)
            }
        }

        /// A mute or pause that still holds, nil for one that ended.
        private static func holding(_ until: Int64?) -> Int64? {
            guard let until else { return nil }
            return until == 0 || until > Int64(Date().timeIntervalSince1970 * 1000) ? until : nil
        }

        /// Until when an admin muted this phone, 0 for until an admin
        /// unmutes it; nil while it is not muted.
        var mutedUntilMS: Int64? { lock.withLock { Self.holding(readMute().mute) } }
        /// Until when sync is off on this phone, in Unix milliseconds; nil
        /// while it is on or off until turned on again.
        var syncOffUntilMS: Int64? {
            guard mode == "own" else { return nil }
            return lock.withLock { readMute().sync.flatMap { $0 > 0 ? $0 : nil } }
        }

        func setMute(_ until: Int64?) throws { try writeMute { $0.mute = until } }

        /// Turns sync on, or off until untilMS (0 for until turned on again).
        func setSync(on: Bool, untilMS: Int64 = 0) throws {
            try set(on ? "shared" : "own")
            try writeMute { $0.sync = on ? nil : untilMS }
        }

        /// Gives a phone that just made or joined a group sync on, as a new
        /// device has it, unless it has its own choice from an earlier group.
        func newDevice() throws {
            if !FileManager.default.fileExists(atPath: url.path) { try set("shared") }
        }

        /// What a command that was taken changes beyond its result: the new
        /// sync mode, or sync away from home turned off.
        enum Change { case mode(String), awayOff, mute }

        /// Carries out a command a member sent: a mode or away-off command
        /// an admin of the group signed for me, not expired and not carried
        /// out before. A phone takes no hub command, no remote paste and no
        /// quick action. Returns the result and what the caller still has to
        /// change.
        func take(_ c: Member.Record, from peer: String?, records: RecordBox, me: String) -> (Member.CommandResult, Change?) {
            let id = Commands.id(of: c) ?? ""
            func refused(_ reason: String) -> (Member.CommandResult, Change?) {
                modeLog.notice("refused a command from \(peer ?? "?", privacy: .public): \(reason, privacy: .public)")
                return (Member.CommandResult(id: id, status: "refused", reason: reason), nil)
            }
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            let body: Commands.Body
            do {
                body = try records.verify(c, me: me, nowMS: now)
            } catch let e as Commands.Refused {
                return refused(e.reason)
            } catch {
                return refused("the command is not valid")
            }
            if body.time_ms < startedMS {
                return refused("this device started after the command was signed, so it may have carried it out already; send it again")
            }
            let again: String? = lock.withLock {
                commands = commands.filter { $0.value > now }
                if commands[body.id] != nil { return "this command was carried out already" }
                if commands.count >= Self.maxCommands { return "too many commands; try again in a minute" }
                commands[body.id] = body.expires_ms
                return nil
            }
            if let again { return refused(again) }
            if body.type == "away-off" {
                modeLog.notice("\(body.by, privacy: .public) turned sync away from home off")
                return (Member.CommandResult(id: body.id, status: "done"), .awayOff)
            }
            switch body.type {
            case "mode":
                break
            case "mute", "unmute":
                let on = body.type == "mute", ms = body.for_ms ?? 0
                do {
                    try setMute(on ? (ms > 0 ? now + ms : 0) : nil)
                } catch {
                    modeLog.error("cannot save the mute: \(String(reflecting: error), privacy: .public)")
                    return (Member.CommandResult(id: body.id, status: "failed", reason: error.localizedDescription), nil)
                }
                modeLog.notice("\(body.by, privacy: .public) \(on ? "muted" : "unmuted", privacy: .public) this phone")
                return (Member.CommandResult(id: body.id, status: "done"), .mute)
            case "paste-off", "actions-off":
                // This phone takes no remote paste and has no quick
                // actions, so nothing of them stays on.
                return (Member.CommandResult(id: body.id, status: "done"), nil)
            case "paste":
                return refused("this phone takes no remote paste")
            case "action":
                return refused("a phone has no quick actions")
            case "hub":
                return refused("a phone does not become the hub by a command")
            default:
                return refused("this phone does not know the command \(body.type)")
            }
            guard let mode = body.mode, Member.modes.contains(mode) else { return refused("unknown sync mode \(body.mode ?? "")") }
            do {
                try set(mode)
            } catch {
                modeLog.error("cannot save the sync mode: \(String(reflecting: error), privacy: .public)")
                return (Member.CommandResult(id: body.id, status: "failed", reason: error.localizedDescription), nil)
            }
            modeLog.notice("\(body.by, privacy: .public) set the sync mode to \(mode, privacy: .public)")
            return (Member.CommandResult(id: body.id, status: "done"), .mode(mode))
        }
    }

    final class RecordBox: @unchecked Sendable {
        private let lock = NSLock()
        private var set: RecordSet
        let groupCA: Data
        var onAdd: (@Sendable (RecordSet) -> Void)?

        init(groupCA: Data, set: RecordSet) { (self.groupCA, self.set) = (groupCA, set) }

        var digest: String? { lock.withLock { set.digest } }
        var all: [Member.Record] { lock.withLock { set.records } }
        var snapshot: RecordSet { lock.withLock { set } }

        func add(_ rs: [Member.Record]) -> [Member.Record] {
            let (fresh, now): ([Member.Record], RecordSet) = lock.withLock {
                (set.addAll(rs, groupCA: groupCA), set)
            }
            if !fresh.isEmpty { onAdd?(now) }
            return fresh
        }

        func replace(_ new: RecordSet) { lock.withLock { set = new } }

        /// How long a copy from another device stays live after it arrives.
        var incomingMS: Int64 { lock.withLock { set.incomingMS } }

        /// Checks a command for me against the records now (Commands.verify),
        /// opening a sealed one with this phone's secret for sealed messages.
        func verify(_ c: Member.Record, me: String, nowMS: Int64) throws -> Commands.Body {
            let secret = try? SealKey.secret()
            return try lock.withLock { try Commands.verify(c, records: set, me: me, nowMS: nowMS, secret: secret) }
        }

        func refused(chain: [Data]) -> String? { lock.withLock { set.refused(chain: chain) } }
        func stopped(chain: [Data]) -> Bool { lock.withLock { set.stopped(chain: chain) } }
        func noSecrets(to device: String?) -> Bool { lock.withLock { set.noSecrets(to: device) } }
    }

    /// Passes what the browser finds to the member, with the computers it
    /// does not find at the addresses they had when admitted, only the
    /// devices that are in the group's list: a removed computer is not
    /// dialed. The member dials each by the addresses Bonjour resolves.
    final class Relay: @unchecked Sendable {
        private let lock = NSLock()
        private var node: CoreMember?
        private var browser: BonjourBrowser?
        private var _allowed: Set<String>? = []
        private var _addresses: [String: [String]] = [:]
        private var last: Set<FoundMember> = []
        /// The devices handed to the member now, with their addresses.
        private var handed: [String: [String]] = [:]
        /// The group tag of the members at known addresses.
        let group: String
        /// This phone's device ID, never dialed: as a hub it announces
        /// itself, and its browser finds that announcement too.
        let device: String

        init(group: String, device: String) {
            self.group = group
            self.device = device
        }

        /// The member that dials what browsing finds, and the browser that
        /// resolves the addresses.
        func attach(node: CoreMember, browser: BonjourBrowser) {
            lock.withLock { (self.node, self.browser) = (node, browser) }
            update(lock.withLock { last })
        }

        /// The device IDs to dial; nil dials every member found.
        var allowed: Set<String>? {
            get { lock.withLock { _allowed } }
            set {
                lock.withLock { _allowed = newValue }
                update(lock.withLock { last })
            }
        }
        /// The known addresses of the computers, by device ID.
        var addresses: [String: [String]] {
            get { lock.withLock { _addresses } }
            set {
                lock.withLock { _addresses = newValue }
                update(lock.withLock { last })
            }
        }
        /// Whether addr is host:port with an IP address, as the member dials.
        static func numeric(_ addr: String) -> Bool {
            guard let (host, _) = JoinCode.split(addr) else { return false }
            return IPv4Address(host) != nil || IPv6Address(host) != nil
        }

        func update(_ found: Set<FoundMember>) {
            let (n, b, members, known): (CoreMember?, BonjourBrowser?, Set<FoundMember>, [String: [String]]) = lock.withLock {
                last = found
                let all = Discovery.withKnown(found, known: Set(_addresses.keys), group: group).filter { $0.group == group && $0.device != device }
                return (node, browser, _allowed.map { a in all.filter { a.contains($0.device) } } ?? all, _addresses)
            }
            guard let n else { return }
            let found = Set(found.map(\.device))
            Task {
                var want: [String: [String]] = [:]
                for m in members {
                    // Browsing's addresses first, then those it had when admitted.
                    let resolved = found.contains(m.device) ? await b?.addresses(of: m.device) ?? [] : []
                    let addrs = resolved + JoinCode.ordered(known[m.device] ?? []).filter { !resolved.contains($0) && Self.numeric($0) }
                    if !addrs.isEmpty { want[m.device] = addrs }
                }
                let (gone, changed): ([String], [String: [String]]) = self.lock.withLock {
                    let gone = self.handed.keys.filter { want[$0] == nil }
                    let changed = want.filter { self.handed[$0.key] != $0.value }
                    self.handed = want
                    return (gone, changed)
                }
                for d in gone { try? n.lost(d) }
                for (d, addrs) in changed { try? n.found(d, addrs: addrs, device: d) }
            }
        }
    }

    /// The copy from another device that waits for this phone, by the
    /// core's rule (docs/design.md, "The one button"): younger than the
    /// group's live window and not yet taken; for what the app takes by
    /// itself (byItself), also while sync is on.
    private func pending(_ node: CoreMember, byItself: Bool) -> CoreMember.Copy? {
        guard !byItself || Member.receives(modeBox.mode) else { return nil }
        return try? node.waiting()
    }

    /// Puts a copy from another device in this phone's clipboard: a text,
    /// an image fetched whole, or files saved in Files, or one image or
    /// video in Photos (true); then it waits no more.
    @discardableResult
    private func take(_ c: CoreMember.Copy) async throws -> Bool {
        var photos = false
        guard let node else { throw PendingGroup.Failure.noComputers }
        if let files = c.media.flatMap({ $0.isFiles ? $0 : nil }) {
            guard await connected(node) else { throw PendingGroup.Failure.noComputers }
            photos = try await save(c, files: files)
        } else if let part = Images.part(of: c.media) {
            try await receive(c, image: part)
        } else if !c.text.isEmpty {
            write(c.text, kind: c.kind)
        }
        try node.took(c.id)
        return photos
    }

    /// What the button says it fetched.
    private func fetched(_ c: CoreMember.Copy, photos: Bool = false) -> AppModel.SyncResult {
        if c.media?.isFiles == true { return .savedFiles(photos: photos) }
        let preview = Images.part(of: c.media) == nil && c.kind == .text ? Self.preview(c.text) : nil
        return .fetched(from: devices.first { $0.id == c.origin && !$0.isSelf }?.name, preview: preview)
    }

    /// Takes the copy that waits for this phone, when one does: at the
    /// app's start or its return to the front, after the computers had a
    /// moment to connect. nil when none waits.
    func takePending() async -> AppModel.SyncResult? {
        guard let node, state != nil else { return nil }
        _ = await connected(node)
        guard let c = pending(node, byItself: true) else { return nil }
        let photos: Bool
        do {
            photos = try await take(c)
        } catch {
            imageLog.error("taking the waiting copy: \(String(reflecting: error), privacy: .public)")
            return nil
        }
        return fetched(c, photos: photos)
    }

    /// The one button, and Back Tap through Shortcuts (docs/design.md, "The
    /// one button"): a copy from another device that waits for this phone
    /// comes in; otherwise what this phone copied goes out, however old,
    /// unless it is the group's copy already or what this phone sent or
    /// took last, as the core's member decides (sends). board is what the
    /// paste button or Shortcuts handed over; without it the button reads
    /// the clipboard, and only when it sends.
    func sync(board given: AppModel.Board?) async throws -> AppModel.SyncResult {
        guard let node, state != nil else { throw PendingGroup.Failure.noComputers }
        online = node.connected()
        if let c = pending(node, byItself: false) {
            let photos = try await take(c)
            return fetched(c, photos: photos)
        }
        let board: AppModel.Board
        if let given { board = given } else { board = try await Self.readBoard() }
        guard let key = board.key, try node.sends(board: key) else {
            if !(await connected(node)) { throw PendingGroup.Failure.noComputers }
            return .nothingNew
        }
        guard await connected(node) else { throw PendingGroup.Failure.noComputers }
        if let image = board.image {
            try node.copyMedia([.data(image.data, type: image.type)], board: true)
        } else if let t = board.text {
            try node.copy(t)
        }
        take(peers: (try? node.peers()) ?? [])
        return .sent(to: devices.filter { $0.online && !$0.isSelf }.map(\.name).sorted())
    }

    /// What the clipboard holds, read by the app itself, which iOS may ask
    /// the user to allow: a text first, as most copies with an image carry
    /// its text too. Read off the main thread: the read waits while iOS
    /// asks, and on the main thread the app froze until the user answered.
    nonisolated private static func readBoard() async throws -> AppModel.Board {
        try await Task.detached(priority: .userInitiated) {
            let pb = UIPasteboard.general
            let text = pb.hasStrings ? pb.string : nil
            let image = text == nil ? Images.read(pb) : nil
            if text == nil, image == nil, pb.numberOfItems > 0 {
                throw ClipboardUnreadable(items: pb.numberOfItems, hasStrings: pb.hasStrings, types: pb.types, changeCount: pb.changeCount)
            }
            return AppModel.Board(text: text, image: image)
        }.value
    }

    /// The start of a text the button fetched, on one line, for the line
    /// that says it is ready to paste.
    nonisolated static func preview(_ text: String, max: Int = 30) -> String {
        let line = text.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        return trimmed.count > max ? String(trimmed.prefix(max)) + "…" : trimmed
    }

    /// Whether a computer is connected, waiting up to connectWait for one:
    /// back from the background, the connections iOS dropped take a moment
    /// to come back. Keeps online, and so the dots, in step.
    private func connected(_ node: CoreMember) async -> Bool {
        let deadline = ContinuousClock.now + Self.connectWait
        while true {
            online = node.connected()
            if !online.isEmpty || ContinuousClock.now >= deadline { return !online.isEmpty }
            try? await Task.sleep(for: .milliseconds(250))
        }
    }

    /// Fetches the images or files of the copy c into a new folder of its
    /// own, which the caller removes; each part with where it is.
    private func fetch(_ c: CoreMember.Copy, limit: Int64) async throws -> (dir: URL, parts: [CoreMember.Fetched]) {
        guard let node else { throw PendingGroup.Failure.noComputers }
        if let size = c.media?.size, size > limit { throw Content.Failure.tooLarge(size: size, limit: limit) }
        if c.unread { throw Content.Failure.unread }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-fetch-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        do {
            return (dir, try await node.fetch(c.id, max: Media.blobSize(limit), into: dir.appendingPathComponent("copy", isDirectory: true)))
        } catch {
            try? FileManager.default.removeItem(at: dir)
            throw error
        }
    }

    /// Fetches the files a computer copied into the app's folder in Files,
    /// Received, with their folders; a name taken there gets a number. One
    /// image or video goes to Photos instead (true) when the user allows it.
    private func save(_ c: CoreMember.Copy, files m: Media.Manifest) async throws -> Bool {
        let fm = FileManager.default
        let root = try fm.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("Received", isDirectory: true)
        // Each top-level name of the copy, made free in Received.
        var renamed: [String: String] = [:]
        func target(_ path: String) -> URL {
            let parts = path.split(separator: "/").map(String.init)
            if renamed[parts[0]] == nil {
                var name = parts[0], n = 2
                let ext = (parts[0] as NSString).pathExtension, base = (parts[0] as NSString).deletingPathExtension
                while fm.fileExists(atPath: root.appendingPathComponent(name).path) {
                    name = ext.isEmpty ? "\(base) (\(n))" : "\(base) (\(n)).\(ext)"
                    n += 1
                }
                renamed[parts[0]] = name
            }
            return parts.dropFirst().reduce(root.appendingPathComponent(renamed[parts[0]]!)) { $0.appendingPathComponent($1) }
        }
        // The copy's sealed blob holds the bytes of all its files, fetched,
        // opened and checked by the member before any is placed.
        let (dir, parts) = try await fetch(c, limit: Images.maxCopy)
        defer { try? fm.removeItem(at: dir) }
        if await Gallery.add(parts, of: m) { return true }
        for p in parts {
            guard let path = p.path, !path.isEmpty else { continue }
            let url = target(path)
            if p.dir {
                try fm.createDirectory(at: url, withIntermediateDirectories: true)
                continue
            }
            try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try fm.moveItem(at: URL(fileURLWithPath: p.file), to: url)
        }
        return false
    }

    /// Fetches a computer's image whole and puts it on this phone's
    /// clipboard, with its text.
    private func receive(_ c: CoreMember.Copy, image part: Media.Part) async throws {
        let (dir, parts) = try await fetch(c, limit: Images.maxCopy)
        defer { try? FileManager.default.removeItem(at: dir) }
        guard let got = parts.first(where: { !$0.dir && $0.type == part.type }) else { throw Content.Failure.noParts }
        let data = try Data(contentsOf: URL(fileURLWithPath: got.file))
        Images.write(data, type: part.type ?? "image/png", alt: c.text)
        await Gallery.keep(data, type: part.type ?? "image/png")
    }

    /// Puts a text into the phone's clipboard; a secret stays on this phone
    /// only and for its remaining minute.
    private func write(_ text: String, kind: Member.Kind) {
        if kind == .secret {
            UIPasteboard.general.setItems([[UTType.plainText.identifier: text]],
                                          options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(Member.secretTTL)])
        } else {
            UIPasteboard.general.string = text
        }
    }
}
