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
    enum Failure: Error, Equatable { case unreachable, noNetwork, timedOut, notAdmin, noWindow, twoWindows, needsRoot, noGroup, rootLeaves([String]), hubUnreachable }

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
    /// How long joining by the six digits browses for a home window, and
    /// then for a second one.
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
    private(set) var state: PhoneGroup?
    /// The saved group was made before 0.6 (D-126): the app says a new
    /// group is needed and offers Leave, which deletes its files.
    private(set) var before06 = false
    /// The phone's member in the Rust core, which syncs (docs/core-api.md,
    /// "The member"), and the task that takes its events.
    private var node: CoreMember?
    private var events: Task<Void, Never>?
    private var browser: BonjourBrowser?
    private var relay: Relay?
    /// Whether the app is in front.
    private var foreground = false
    /// Whether the app is in the background, where the member closes its
    /// connections and makes none, but for a background refresh.
    private var background = false
    private var online: Set<String> = []
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
    /// The user's last Face ID check, good for authorizedFor.
    private let authorization = Authorization(lasts: LiveGroup.authorizedFor)

    /// In the app group's container, where the share extension reads it.
    nonisolated static var defaultFile: URL { Shared.groupFile }

    init(file: URL = LiveGroup.defaultFile) {
        self.file = file
        modeBox = ModeBox(url: file.deletingLastPathComponent().appendingPathComponent("mode"))
        do {
            state = try PhoneGroup.load(from: file)
        } catch is PhoneGroup.Before06 {
            before06 = true
        } catch {
            keysLog.error("the saved group does not read: \(String(reflecting: error), privacy: .public)")
        }
        try? startSync()
        // The phone locked with the app in front: the keys sign without
        // asking no more, as when the app goes to the background.
        let authorization = authorization
        NotificationCenter.default.addObserver(forName: UIApplication.protectedDataWillBecomeUnavailableNotification,
                                               object: nil, queue: nil) { _ in authorization.end() }
    }

    var hasGroup: Bool { state != nil || before06 }

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
    /// Has the phone's member in the core build, check and sign one of the
    /// root's own records with the root key (cbb_member_manage), which it adds
    /// and sends.
    @discardableResult
    private func rootRecord<T>(_ root: SecKeySigner, _ act: (CoreMember, Data, @escaping (Data) throws -> Data) throws -> T) throws -> T {
        guard let node else { throw CoreMember.Failure.notConnected }
        let out = try act(node, root.publicKeyDER, { try root.signature(digest: $0) })
        Task { await refresh() }
        return out
    }

    /// An action of this phone's root or admin key (cbb_member_manage):
    /// after Face ID the member signs it and the records judge whether the
    /// key may; a command a device refused throws CommandRefused.
    @discardableResult
    private func act(_ reason: String, _ action: String, _ fields: [String: CoreMember.ManageValue] = [:]) async throws -> [String: CoreMember.ManageValue] {
        guard let node else { throw CoreMember.Failure.notConnected }
        let ca = try await caSigner(reason: reason)
        var request = fields
        request["action"] = .string(action)
        let r = try await Task.detached(priority: .userInitiated) {
            try node.act(request, public: ca.publicKeyDER) { try ca.signature(digest: $0) }
        }.value
        if let status = r["status"]?.string, status != "done" { throw CommandRefused(reason: r["reason"]?.string ?? status) }
        await refresh()
        return r
    }

    var keyLevel: String? { state?.isRoot == true ? group06?.keyLevel : nil }

    /// How long a copy and a secret live, in milliseconds, as the group's
    /// records set them (D-129).
    var ttlMS: (copy: Int64, secret: Int64) {
        (group06?.ttlMS ?? Records.defaultTtlMS, group06?.secretTtlMS ?? Records.defaultSecretTtlMS)
    }

    /// Sets how long a copy (ms) or a secret (secretMS) lives, the other
    /// nil to keep it: a copies record, signed after Face ID by the root or
    /// an admin and sent to every member (docs/protocol.md, section 10,
    /// "The copies setting").
    func setTtl(ms: Int64?, secretMS: Int64?) async throws {
        guard state?.isAdmin == true else { throw PhoneGroup.Failure.notAdmin }
        var fields: [String: CoreMember.ManageValue] = [:]
        if let ms { fields["ttl_ms"] = .int(ms) }
        if let secretMS { fields["secret_ttl_ms"] = .int(secretMS) }
        try await act(String(localized: "Change how long copies and secrets last", bundle: .app), "ttl", fields)
    }

    /// Sets the group's key level (docs/guide/keys.md, "The three levels"):
    /// a settings record, signed with the root key after Face ID and sent
    /// to every member, which keeps the takeover delay.
    func setKeyLevel(_ level: String) async throws {
        guard state?.isRoot == true else { throw PhoneGroup.Failure.notRoot }
        let root = try await caSigner(reason: String(localized: "Change which keys may be admins", bundle: .app))
        // A phone's keys are in its hardware.
        guard Records.levelAllows(level, store: Records.hardware, consent: true) else { throw PhoneGroup.Failure.belowKeyLevel }
        try rootRecord(root) { n, p, s in try n.setKeyLevel(level, public: p, sign: s) }
    }

    /// The label of the key this phone signs with: the root key, or the
    /// admin key of a phone that joined.
    nonisolated static func signingLabel(_ g: PhoneGroup?) -> String { g?.isRoot == false ? adminLabel : caLabel }

    var computers: [AppModel.Computer] {
        devices.filter { !$0.isSelf }
    }

    var devices: [AppModel.Computer] {
        guard let g = state else { return [] }
        return devices06(g)
    }

    func refresh() async {
        let before = online
        take(peers: (try? node?.peers()) ?? [])
        if let gs = try? node?.group() {
            group06 = gs
            state?.admin06 = gs.me.admin
        }
        takePush()
        if let n = node, let ns = try? n.notices() { notices = ns }
        if !online.subtracting(before).isEmpty { syncedSoon() }
    }

    // MARK: The group in 0.6

    /// The member's state of a group of 0.6, as the last refresh read it.
    private var group06: GroupState?

    /// The devices of a group of 0.6, as its member's state names them,
    /// with what the connected ones' hellos say.
    private func devices06(_ g: PhoneGroup) -> [AppModel.Computer] {
        guard let gs = group06 else { return [] }
        return gs.devices.map {
            let me = $0.device == g.device
            return .init(id: $0.device, name: $0.name, online: me || online.contains($0.device), role: $0.role == "computer" ? "member" : $0.role,
                         os: $0.os.isEmpty ? nil : $0.os, isSelf: me, admin: $0.admin, isRoot: $0.device == gs.rootDevice,
                         canMakeAdmin: gs.isRoot && !me && $0.offersAdmin, keysInFile: keyStores[$0.device] == Records.file, frozen: $0.frozen,
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
    func newGroup() async throws -> Core.RecoverySheet {
        guard state == nil else { throw Failure.noGroup }
        let root = try await newRootKey(reason: String(localized: "Add a computer to your group", bundle: .app))
        let member = try memberSigner()
        try FileManager.default.createDirectory(at: memberDir, withIntermediateDirectories: true)
        let made = try CorePairing.newGroup(dir: memberDir, name: PhoneGroup.validName(UIDevice.current.name), store: Records.hardware,
                                            rootPublic: root.publicKeyDER, publicKey: member.publicKeyDER) { try root.signature(digest: $0) }
        let g = PhoneGroup.of06(device: made.device, group: made.group, root: true)
        try g.save(to: file)
        try modeBox.newDevice()
        state = g
        try startSync()
        await refresh()
        let text = made.recovery.text.flatMap { $0.split(separator: " ").map(String.init) }.joined(separator: "-")
        return Core.RecoverySheet(qr: made.recovery.qr, text: text)
    }

    /// Opens this phone's home window on a group of 0.6 (docs/protocol.md,
    /// "Pairing in 0.6"): the member port listens, the window is announced
    /// by Bonjour, and shown gets the QR code and the six digits. A device
    /// that dials proves the digits; nobody is asked. Returns the name of
    /// the device that joined; the window closes when it does, when its
    /// time is up, after three wrong codes, or when the task is cancelled.
    func openWindow(shown: @escaping @MainActor (_ qr: String, _ digits: String) -> Void) async throws -> String {
        guard let g = state, g.isAdmin else { throw Failure.noGroup }
        guard let node else { throw Failure.unreachable }
        let signer = try await caSigner(reason: String(localized: "Add a computer to your group", bundle: .app))
        let port = try node.listen(.home, port: 0)
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
                state = g
                try startSync()
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

    func rootChangeSeen() {
        rootChanged = nil
        do {
            try node?.rootChangeSeen()
        } catch {
            syncLog.error("cannot note that the change of root was seen: \(String(reflecting: error), privacy: .public)")
        }
    }

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
        infos = Dictionary(ps.compactMap { p in p.info.map { (p.device, $0) } }, uniquingKeysWith: { a, _ in a })
        modes = Dictionary(ps.compactMap { p in p.mode.isEmpty ? nil : (p.device, p.mode) }, uniquingKeysWith: { a, _ in a })
        mutes = Dictionary(ps.compactMap { p in p.mutedUntilMS().map { (p.device, $0) } }, uniquingKeysWith: { a, _ in a })
        actions = Dictionary(ps.map { ($0.device, $0.actions) }, uniquingKeysWith: { a, _ in a })
        keyStores = Dictionary(ps.compactMap { p in p.keyStore.isEmpty ? nil : (p.device, p.keyStore) }, uniquingKeysWith: { a, _ in a })
    }

    /// The group's records count as synced with a member once one has
    /// stayed connected for 30 s (the member takes its records at the
    /// connection's start): that spends the push hints-only marks from
    /// before which the records contradict.
    private func syncedSoon() {
        let before = Set(((try? node?.peers()) ?? []).map(\.device))
        guard !before.isEmpty else { return }
        let since = Date()
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(30))
            guard let self, let node = self.node else { return }
            let now = Set(((try? node.peers()) ?? []).map(\.device))
            let stayed = now.intersection(before)
            if !stayed.isEmpty { PushSetup.shared.synced(at: since, peers: stayed, recordsAt: nil) }
        }
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

    private func memberSigner() throws -> SecKeySigner {
        try SecKeySigner(key(label: Self.memberLabel, secureEnclave: false))
    }

    // MARK: Inviting from afar

    /// Opens a remote invitation through a hub of the group
    /// (docs/protocol.md, section 12, "Through the hub"): the core opens the
    /// guest tunnel on a connected hub and runs the pairing window here, the
    /// hub passing the pairing's bytes, for one device, for lifetime
    /// seconds. ask asks the user whether to admit a device that proved it
    /// knows the secret; on yes Face ID unlocks the group's key. ended gets
    /// the admitted device's name, or why the invitation ended without one.
    func invite(lifetime: Int, ask: @escaping @MainActor (CorePairing.Inviting.Request) async -> Bool,
                ended: @escaping @MainActor (Result<String, Error>) -> Void) async throws -> AppModel.Invitation {
        guard let g = state, g.isAdmin else { throw Failure.notAdmin }
        guard let node else { throw CoreMember.Failure.notConnected }
        let unlocked = UnlockedSigner()
        // The key's public half needs no Face ID; its signature does.
        guard let k = try KeychainIdentity.loadKey(label: Self.signingLabel(g)) else { throw Failure.notAdmin }
        let publicKey = try SecKeySigner(k).publicKeyDER
        let inviting = try await Task.detached(priority: .userInitiated) {
            try CorePairing.Inviting(member: node, publicKey: publicKey, expires: lifetime) { digest in
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
                    guard let req = st.request else { continue }
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
    private func confirmInvited(_ req: CorePairing.Inviting.Request, ask: @MainActor (CorePairing.Inviting.Request) async -> Bool, reason: String,
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

    /// Removes a device from the group: a removal signed with this phone's
    /// root or admin key after Face ID, which the member sends to every
    /// member; they refuse the device from then on. The root changes only
    /// by the recovery key (changeRoot).
    func remove(_ id: String) async throws {
        try await act(String(localized: "Remove a device from your group", bundle: .app), "remove", ["device": .string(id)])
    }

    /// Whether the group removed this phone: its state, once the member
    /// read one, no longer lists it. The app then offers to leave.
    var removed: Bool {
        guard let g = state, let gs = group06, !gs.devices.isEmpty else { return false }
        return !gs.devices.contains { $0.device == g.device }
    }

    /// Takes this phone out of its group (D-83, docs/design.md, "Leaving
    /// the group"): it stops syncing and deletes its keys, the group's
    /// files and the tunnel's settings; the sync mode stays. The phone can
    /// then make a group or join one again. The root leaves only when the
    /// group has no other devices than itself and its watch: nobody could
    /// add or remove one after it. The group keeps listing the phone
    /// until an admin removes it.
    func leave() async throws {
        guard state != nil || before06 else { throw Failure.noGroup }
        if let g = state, g.isRoot {
            let others = (group06?.devices ?? []).filter { $0.device != g.device && $0.role != "watch" }.map(\.name)
            if !others.isEmpty { throw Failure.rootLeaves(others) }
        }
        stopNode()
        for label in [Self.caLabel, Self.adminLabel, Self.memberLabel] {
            KeychainIdentity.removeKey(label: label)
            KeychainIdentity.removePublicKeys(label: label)
            KeychainIdentity.removeCertificates(label: label)
        }
        // What Share left for the group, and what a group from before 0.6
        // kept beside the group's file.
        let dir = file.deletingLastPathComponent()
        for url in [file, memberDir] + ["credentials.json", "entries.json", "attest-status", "share-queue"].map(dir.appendingPathComponent) {
            try? FileManager.default.removeItem(at: url)
        }
        (online, keyStores, infos, modes, actions, mutes) = ([], [:], [:], [:], [:], [:])
        authorization.end()
        (state, group06, before06) = (nil, nil, false)
        keysLog.notice("this phone left its group: its keys and the group's files are deleted")
    }

    /// Unfreezes an admin computer that another admin froze
    /// (docs/protocol.md, section 10, "Removals and freezes keep what the author saw"): a thaw record signed with this
    /// phone's root or admin key, after Face ID, sent to every connected
    /// computer.
    func unfreeze(_ id: String) async throws {
        try await act(String(localized: "Unfreeze an admin computer", bundle: .app), "thaw", ["device": .string(id)])
    }

    /// Freezes an admin computer, as one does with a stolen one.
    func freeze(_ id: String) async throws {
        try await act(String(localized: "Freeze an admin computer", bundle: .app), "freeze", ["device": .string(id)])
    }

    /// Makes an admin computer a hub through the project's forwarder; the
    /// computer answers whether it is one.
    func makeHub(_ id: String) async throws {
        try await act(String(localized: "Make a computer a hub", bundle: .app), "hub", ["device": .string(id)])
    }

    /// Gives a device another name (docs/protocol.md, section 10): a device
    /// record like its newest one with that name, signed with this phone's
    /// root or admin key after Face ID, sent to every connected computer.
    func rename(_ id: String, to name: String) async throws {
        guard state?.isAdmin == true else { throw PhoneGroup.Failure.notAdmin }
        try await act(String(localized: "Rename a device", bundle: .app), "rename", ["device": .string(id), "name": .string(name)])
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
        try await act(String(localized: "Change a computer's sync mode", bundle: .app), mode == "own" ? "sync_off" : "sync_on", ["device": .string(id)])
    }

    /// Turns sync on this phone on, or off for forMS milliseconds, 0 for
    /// until turned on again (design.md, "Sync on and off"): off, the
    /// clipboard is this phone's own, both ways. Needs no rights.
    func setSync(_ on: Bool, forMS: Int64) throws {
        try modeBox.setSync(on: on, untilMS: !on && forMS > 0 ? Int64(Date().timeIntervalSince1970 * 1000) + forMS : 0)
        try? node?.setSync(on: on, forMS: on ? 0 : forMS)
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
        if on {
            try await act(String(localized: "Mute a device", bundle: .app), "mute", ["device": .string(id), "for_ms": .int(forMS)])
        } else {
            try await act(String(localized: "Unmute a device", bundle: .app), "unmute", ["device": .string(id)])
        }
    }

    /// Puts text where the focus of a computer is (design.md, "Remote
    /// paste"): a paste command signed with this phone's root or admin key
    /// after Face ID, passed on by a hub of the group connected to it when this phone
    /// is not; the computer answers once the text is in, or why not.
    func paste(_ id: String, text: String, method: String, enter: Bool, secret: Bool) async throws {
        try await act(String(localized: "Paste on a device", bundle: .app), "paste",
                      ["device": .string(id), "text": .string(text), "method": .string(method), "enter": .bool(enter),
                       "kind": .string(secret ? "secret" : "text")])
    }

    /// Pastes a picture or files where a computer's focus is
    /// (docs/protocol.md, section 15): they go to the group as a copy, then
    /// a paste command of kind media names that copy; the computer fetches
    /// it, puts it in its clipboard and presses the paste keys.
    func pasteMedia(_ id: String, parts: [CoreMember.Part], enter: Bool) async throws {
        guard let node else { throw CoreMember.Failure.notConnected }
        _ = try node.copyMedia(parts)
        try await act(String(localized: "Paste on a device", bundle: .app), "paste",
                      ["device": .string(id), "kind": .string("media"), "enter": .bool(enter)])
    }

    /// Runs a quick action on a device (docs/protocol.md, section 15): an
    /// action command, signed with this phone's root or admin key after Face
    /// ID, names it; the device defines what it does and runs it only when
    /// its user turned it on there.
    func runAction(_ id: String, name: String) async throws {
        try await act(String(localized: "Run a quick action", bundle: .app), "action", ["device": .string(id), "name": .string(name)])
    }

    /// Turns every quick action off on a device; only its user turns them
    /// on again.
    func actionsOff(_ id: String) async throws {
        try await act(String(localized: "Run a quick action", bundle: .app), "actions_off", ["device": .string(id)])
    }

    /// Makes a phone or a computer an admin (docs/protocol.md, section 10,
    /// "Admins"): the root key, after Face ID, signs the device's new
    /// record, which the member sends to every member.
    func makeAdmin(_ id: String) async throws {
        // The dialog before it warned when the computer's keys sit in a file.
        try await makeAdmin(id, allowFileKey: true)
    }

    /// Adds the group's watch with its key (docs/protocol.md, section 10,
    /// "Watches"): the root key, after Face ID, signs its device record with
    /// the role watch, which the member sends to every member. On 0.6 the
    /// watch shows the group and signs nothing (D-124).
    func addWatch(_ request: WatchState.KeyRequest) async throws -> WatchState.Admission {
        guard state?.isRoot == true else { throw PhoneGroup.Failure.notRoot }
        let a = try await act(String(localized: "Make the watch an admin", bundle: .app), "add_watch",
                              ["key": .string(request.key.base64EncodedString()), "name": .string(request.name), "os": .string("watchos")])
        return WatchState.Admission(device: a["device"]?.string ?? request.device, adminCA: Data(), group: state?.tag ?? "")
    }

    /// The watch signs nothing from the wrist on 0.6 (D-124).
    func watchActions(for _: String) -> [String] { [] }

    func watchBody(_: WatchState.Ask) throws -> Data { throw PhoneGroup.Failure.notForWatch }

    func deliverFromWatch(_: WatchState.Signed) async throws {
        throw PhoneGroup.Failure.notForWatch
    }

    /// Makes a phone or a computer an admin; a computer whose keys sit in a
    /// file only with allowFileKey, else PhoneGroup.Failure.fileKey; a
    /// rootless install never (PhoneGroup.Failure.rootless). A phone keeps
    /// the store its record names.
    private func makeAdmin(_ id: String, allowFileKey: Bool) async throws {
        guard state?.isRoot == true else { throw Failure.notAdmin }
        let peer = ((try? node?.peers(all: true)) ?? []).first { $0.device == id }
        let phone = peer?.role == "phone"
        let store = phone ? nil : peer.flatMap { $0.keyStore.isEmpty ? nil : $0.keyStore }
        if !phone {
            guard Records.store(store, role: "member") != Records.rootless else { throw PhoneGroup.Failure.rootless }
            guard Records.store(store, role: "member") == Records.hardware || allowFileKey else { throw PhoneGroup.Failure.fileKey }
        }
        let reason = String(localized: "Make a device an admin", bundle: .app)
        // The user's consent to a key in a file, after the dialog's
        // warning, lets the group take keys in files too.
        if !phone, Records.store(store, role: "member") == Records.file, allowFileKey, keyLevel != Records.levelFiles {
            try await act(reason, "key_level", ["level": .string(Records.levelFiles)])
        }
        try await act(reason, "make_admin", ["device": .string(id), "allow_file_key": .bool(allowFileKey)])
    }

    /// A new root key in the Secure Enclave, behind Face ID, for a new group
    /// or a change of root; a root key left from an earlier group goes.
    private func newRootKey(reason: String) async throws -> SecKeySigner {
        KeychainIdentity.removeKey(label: Self.caLabel)
        let se = Self.secureEnclave
        _ = try KeychainIdentity.makeKey(label: Self.caLabel, secureEnclave: se, userPresence: se)
        return try await signer(label: Self.caLabel, reason: reason)
    }

    // MARK: Syncing

    /// The folder where the phone's member in the core keeps the group's
    /// set and the images and files, beside the group's file.
    private var memberDir: URL { file.deletingLastPathComponent().appendingPathComponent("member", isDirectory: true) }

    /// Starts the phone's member in the core and finding the computers,
    /// once there is a group.
    private func startSync() throws {
        guard let g = state, node == nil else { return }
        let signer = try memberSigner()
        try FileManager.default.createDirectory(at: memberDir, withIntermediateDirectories: true)
        let node = try CoreMember(.init(dir: memberDir, name: UIDevice.current.name, osVersion: Self.ownDevice.osVersion ?? "",
                                        version: Self.ownDevice.version ?? "", device: g.device,
                                        publicKeyDER: signer.publicKeyDER)) { try signer.signature(digest: $0) }
        try node.setSync(on: modeBox.mode != "own", forMS: modeBox.syncOffUntilMS.map { max(1, $0 - Int64(Date().timeIntervalSince1970 * 1000)) } ?? 0)
        if let muted = modeBox.mutedUntilMS { try node.setMute(untilMS: muted) }
        // The app browses itself: the core's own mDNS would need the
        // multicast entitlement.
        let relay = Relay(group: g.tag, device: g.device)
        let browser = BonjourBrowser(log: { browseLog.notice("\($0, privacy: .public)") }) { found in relay.update(found) }
        relay.attach(node: node, browser: browser)
        browser.start()
        (self.node, self.browser, self.relay) = (node, browser, relay)
        events = Task { @MainActor [weak self] in
            for await e in node.events { self?.handled(e) }
        }
        if background { try? node.pause() }
        // Push: the member sends the group's registration to every member
        // it connects to.
        PushSetup.shared.sink = { [weak self] frame in
            guard let self, let node = self.node else { return }
            do { try node.setPush(frame) } catch {
                modeLog.error("handing the member the push registration: \(String(reflecting: error), privacy: .public)")
            }
        }
        try? node.setPush(PushSetup.shared.frame())
        Task { await sendShared() }
    }

    /// Sends what Share handed the app (ShareQueue), oldest first, once a
    /// device of the group is connected; what does not go stays for the
    /// next time.
    private func sendShared() async {
        let waiting = ShareQueue.items()
        guard !waiting.isEmpty, let node, await connected(node) else { return }
        for (folder, item) in waiting {
            do {
                if let text = item.text {
                    try node.copy(text, board: false)
                } else {
                    let parts: [CoreMember.Part] = try item.parts.map { p in
                        let data = try Data(contentsOf: folder.appendingPathComponent(p.file))
                        return p.path.map { .bytes(data, path: $0) } ?? .data(data, type: p.type ?? "application/octet-stream")
                    }
                    if !parts.isEmpty { _ = try node.copyMedia(parts) }
                }
                ShareQueue.remove(folder)
            } catch {
                syncLog.error("sending what was shared: \(String(reflecting: error), privacy: .public)")
                return
            }
        }
    }

    /// The group's face toward the push service and each `push-renew`
    /// members sent: the group registers with the face, and again for each
    /// renewal.
    private func takePush() {
        guard let node else { return }
        PushSetup.shared.face(try? node.pushFace())
        for r in (try? node.pushRenewals()) ?? [] { PushSetup.shared.renew(slot: r.slot, ahead: r.ahead) }
    }

    /// What the member's events change on the main actor: the copies that
    /// come in, the group's state, mutes and sync modes, the log.
    private func handled(_ e: CoreMember.Event) {
        switch e {
        case let .copy(c):
            // A copy from another device (docs/design.md, "Sync model",
            // D-128): Home shows it as the last received, and while the app
            // is on the screen the phone listens like a computer and writes
            // it, whatever its age; in the background it writes nothing.
            guard let g = state, c.origin != g.device, !c.unread, c.media?.isFiles != true else { return }
            let image = Images.part(of: c.media) != nil
            guard image || (!c.text.isEmpty && c.kind != .media) else { return }
            let ttl = c.ttlMS ?? (c.kind == .secret ? Records.defaultSecretTtlMS : Records.defaultTtlMS)
            let until = Date().addingTimeInterval(Double(max(ttl - c.ageMS, 0)) / 1000)
            lastReceived = AppModel.Received(id: c.id, from: name(of: c.origin), text: c.kind == .secret ? "" : c.text, until: until)
            onReceived?(lastReceived)
            guard foreground, !background, Member.receives(modeBox.mode) else { return }
            Task {
                do {
                    try await take(c)
                } catch {
                    imageLog.error("taking a copy: \(String(reflecting: error), privacy: .public)")
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

    /// Stops syncing and starts again.
    private func restartSync() async {
        stopNode()
        try? startSync()
    }

    /// Stops the member, its events and the browsing.
    private func stopNode() {
        events?.cancel()
        browser?.stop()
        node?.stop()
        (node, events, browser, relay) = (nil, nil, nil, nil)
    }

    /// Tells the group the app came to the front or went to the background.
    func setForeground(_ on: Bool) {
        foreground = on
        // Back at the front the member connects at once, and without a
        // computer browsing starts again too, as iOS may have ended it.
        guard on, let node else { return }
        background = false
        try? node.resume()
        if node.connected().isEmpty { browser?.restart() }
        Task { await renewPeriod06() }
        Task { await sendShared() }
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

    // MARK: Away and the relay on 0.6

    /// On a group of 0.6, sync away from home as the Live member runs it; nil while it is off.
    private var awayState06: CoreMember.AwayState? { try? node?.awayStatus() }


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

    /// Why the phone does not sync (docs/apps.md, "Why it does not sync"),
    /// as the member says: it runs the tunnel itself and says where it
    /// stands.
    func why() async -> [WhyReason] {
        guard let node else { return [WhyReason(code: "not_in_group", level: "stop")] }
        return (try? node.why(away: nil)) ?? []
    }

    /// The blind relay as Settings shows it; nil without a group.
    func relayStatus() async -> AppModel.BlindRelay? {
        guard state != nil else { return nil }
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

    /// Sync away from home as Settings shows it; nil without a group.
    func awayStatus() async -> (on: Bool, status: AwayFromHome.Status, error: Error?, hub: String?, hubs: [String])? {
        guard let node else { return nil }
        let a = awayState06
        let connected = Set(node.connected())
        let status = AwayOn06.awayStatus(a) { connected.contains($0) }
        let error = a.flatMap { $0.error.isEmpty ? nil : Away06Failure(message: AwayOn06.reason($0.error, $0.detail)) }
        let hub = a.flatMap { $0.hubDevice.isEmpty || status == .connecting ? nil : $0.hubDevice }
        return (a?.isOn == true && a?.hub != true, status, error, hub, a.map { $0.hubDevice.isEmpty ? [] : [$0.hubDevice] } ?? [])
    }

    /// Turns sync away from home on or off.
    func setAwayFromHome(_ on: Bool) async throws {
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

    /// This phone's sync mode (docs/design.md, "Sync modes"), in the file
    /// mode beside the group's, as the computers keep it, shared when there
    /// is none.
    final class ModeBox: @unchecked Sendable {
        private let lock = NSLock()
        private let url: URL

        /// A sync mode other than own, shared, receive and send.
        struct UnknownMode: Error { let mode: String }

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
            guard Member.modes.contains(mode) else { throw UnknownMode(mode: mode) }
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
    }

    /// Passes the members of the group that the browser finds to the
    /// member, which dials each by the addresses Bonjour resolves; the
    /// group refuses a removed device itself.
    final class Relay: @unchecked Sendable {
        private let lock = NSLock()
        private var node: CoreMember?
        private var browser: BonjourBrowser?
        private var last: Set<FoundMember> = []
        /// The devices handed to the member now, with their addresses.
        private var handed: [String: [String]] = [:]
        /// The group tag the members publish.
        let group: String
        /// This phone's device ID, never dialed: its browser may find its
        /// own home window's announcement.
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

        /// Whether addr is host:port with an IP address, as the member dials.
        static func numeric(_ addr: String) -> Bool {
            guard let (host, _) = LocalAddresses.split(addr) else { return false }
            return IPv4Address(host) != nil || IPv6Address(host) != nil
        }

        func update(_ found: Set<FoundMember>) {
            let (n, b, members): (CoreMember?, BonjourBrowser?, Set<FoundMember>) = lock.withLock {
                last = found
                return (node, browser, found.filter { $0.group == group && $0.device != device })
            }
            guard let n else { return }
            Task {
                var want: [String: [String]] = [:]
                for m in members {
                    let addrs = (await b?.addresses(of: m.device) ?? []).filter(Self.numeric)
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
            write(c.text, kind: c.kind, ttlMS: c.ttlMS)
        }
        try node.took(c.id)
        // The app's own write is no copy: the next opening does not send it.
        seen(UIPasteboard.general.changeCount, key: c.media == nil && !c.text.isEmpty ? c.text : nil)
        return photos
    }

    /// What the button says it fetched.
    private func fetched(_ c: CoreMember.Copy, photos: Bool = false) -> AppModel.SyncResult {
        if c.media?.isFiles == true { return .savedFiles(photos: photos) }
        let preview = Images.part(of: c.media) == nil && c.kind == .text ? Self.preview(c.text) : nil
        return .fetched(from: devices.first { $0.id == c.origin && !$0.isSelf }?.name, preview: preview)
    }

    /// The last copy that came from another device, for Home's line (D-128).
    private(set) var lastReceived: AppModel.Received?
    /// Tells the app the last received copy changed.
    var onReceived: ((AppModel.Received?) -> Void)?

    /// Copy on Home's last received line: the copy goes into the clipboard
    /// and the line goes. nil when the group holds a newer copy now.
    func copyReceived(_ id: String) async throws -> AppModel.SyncResult? {
        guard let node else { throw PendingGroup.Failure.noComputers }
        lastReceived = nil
        onReceived?(nil)
        guard let c = try node.current(), c.id == id else { return nil }
        let photos = try await take(c)
        return fetched(c, photos: photos)
    }

    /// The clipboard's change count as the app last saw it (D-128): opening
    /// compares it to tell a copy made since. It keeps across starts.
    private var seenCount: Int {
        get { UserDefaults.standard.object(forKey: Self.seenCountKey) as? Int ?? -1 }
        set { UserDefaults.standard.set(newValue, forKey: Self.seenCountKey) }
    }
    nonisolated static let seenCountKey = "BoardSeen"
    /// The clipboard's key as the app last saw it, while it runs; nil when
    /// it does not know.
    private var seenKey: String?

    private func seen(_ count: Int, key: String?) {
        seenCount = count
        seenKey = key
    }

    /// The app's opening (docs/design.md, "The one button", D-128): it swaps
    /// nothing. A clipboard changed since the app last saw it (the change
    /// count) goes out, when the user lets the app read it (mayRead);
    /// otherwise the phone takes the group's copy. A changed clipboard the
    /// app may not read stays as it is. nil when nothing went either way.
    func opened(mayRead: Bool) async throws -> AppModel.SyncResult? {
        guard let node, state != nil else { return nil }
        _ = await connected(node)
        let count = UIPasteboard.general.changeCount
        let changed = count != seenCount
        if changed && !mayRead { return nil }
        let board: AppModel.Board? = changed ? try await Self.readBoard() : nil
        let key = changed ? (board?.key ?? "") : (seenKey ?? "")
        seen(count, key: key.isEmpty ? nil : key)
        let s = try node.opened(board: key, changed: changed)
        if s.sends, let board { return try await send(board, node) }
        guard let c = s.copy, Member.receives(modeBox.mode) else { return nil }
        let photos = try await take(c)
        return fetched(c, photos: photos)
    }

    /// The one button, and Back Tap through Shortcuts (docs/design.md, "The
    /// one button", D-128): a strict swap. What the clipboard holds goes to
    /// the group and the group's copy comes into the clipboard; an empty
    /// clipboard, or one holding the group's copy, only takes. board is
    /// what the paste button or Shortcuts handed over; without it the
    /// button reads the clipboard.
    func sync(board given: AppModel.Board?) async throws -> AppModel.SyncResult {
        guard let node, state != nil else { throw PendingGroup.Failure.noComputers }
        online = node.connected()
        let board: AppModel.Board
        if let given { board = given } else { board = try await Self.readBoard() }
        let s = try node.swap(board: board.key ?? "")
        var sent: AppModel.SyncResult?
        if s.sends { sent = try await send(board, node) }
        guard let c = s.copy else {
            if let sent { return sent }
            if !(await connected(node)) { throw PendingGroup.Failure.noComputers }
            return .nothingNew
        }
        let photos = try await take(c)
        let got = fetched(c, photos: photos)
        if sent != nil, case let .fetched(from, preview) = got { return .swapped(from: from, preview: preview) }
        return got
    }

    /// Sends what the clipboard held to the group.
    private func send(_ board: AppModel.Board, _ node: CoreMember) async throws -> AppModel.SyncResult {
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

    /// How long a secret stays in the clipboard when it carries no lifetime
    /// of its own (docs/design.md, "Secrets"; D-129).
    nonisolated static let secretTTL: TimeInterval = 60

    /// Puts a text into the phone's clipboard; a secret stays on this phone
    /// only and for its lifetime, as its sender stamped it.
    private func write(_ text: String, kind: Member.Kind, ttlMS: Int64? = nil) {
        if kind == .secret {
            let ttl = ttlMS.map { TimeInterval($0) / 1000 } ?? Self.secretTTL
            UIPasteboard.general.setItems([[UTType.plainText.identifier: text]],
                                          options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(ttl)])
        } else {
            UIPasteboard.general.string = text
        }
    }
}
