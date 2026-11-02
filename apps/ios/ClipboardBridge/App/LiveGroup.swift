// SPDX-License-Identifier: AGPL-3.0-only

import ClipboardBridgeKit
import CryptoKit
import Foundation
import LocalAuthentication
import Network
import os
import Security
import UIKit
import UniformTypeIdentifiers

private let awayLog = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "away")
private let relayLog = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "relay")
private let browseLog = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "browse")
private let hubLog = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "hub")
private let modeLog = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "mode")
private let keysLog = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "keys")
private let imageLog = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "images")

/// The phone's own group (docs/protocol.md, section 9): its root CA key in
/// the Secure Enclave, signing only after Face ID or the passcode (a
/// keychain key where there is no Secure Enclave, as in the simulator), its
/// member key in the keychain, the group in Application Support. While there is a group it finds the computers,
/// keeps a connection to each, and syncs with them.
@MainActor
final class LiveGroup: GroupController {
    enum Failure: Error { case unreachable, notConfirmed, noNetwork, timedOut, tooManyWrongCodes, notAdmin }

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

    nonisolated static let caLabel = "io.github.hunterewok.clipboardbridge.group-root"
    /// The admin key of a phone that joined another phone's group.
    nonisolated static let adminLabel = "io.github.hunterewok.clipboardbridge.admin"
    /// How long the join QR code is good for, and how many wrong codes it
    /// takes, as for cbb pair (docs/protocol.md, section 6).
    static let joinWindow: TimeInterval = 300
    /// How long admitting a device may take once its connection is up:
    /// a computer that stops answering mid-pairing fails then.
    static let pairingDeadline: Duration = .seconds(30)
    static let joinAttempts = 3
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
    /// How recent a computer's copy must be for the button to fetch it
    /// first, as for the shortcut (internal/phone/sync.go).
    static let recentCopyMS: Int64 = 45_000
    /// How long the button waits for a computer to connect before it says
    /// none is.
    static let connectWait: Duration = .seconds(5)

    let file: URL
    /// The revocation list the root checks evidence against.
    private let attestStatus: AttestStatus
    private(set) var state: PhoneGroup?
    private var node: MemberNode?
    /// The images this phone copied, which the computers fetch from it.
    private let content = MemoryContent(maxBytes: 2 * Images.maxCopy)
    private var browser: BonjourBrowser?
    private var dialer: MemberDialer?
    private var relay: Relay?
    private var recordBox: RecordBox?
    /// The group's server credentials (docs/protocol.md, section 18) and
    /// this phone's keys for the servers.
    private var credentialBox: CredentialBox?
    private let periodKeys = PhoneKeys()
    private var renewer: Renewer?
    private var admins: AdminBox?
    private var away: AwayFromHome?
    /// The phone as the group's hub, and while it runs its member
    /// listeners: on the loopback address for the tunnel, and on a home
    /// network, published by Bonjour.
    private var hub: HubOnPhone?
    private var tunnelListener: (listener: MemberListener, port: UInt16)?
    private var homeListener: MemberListener?
    /// The phone at a blind relay, and while it runs its member listener on
    /// the loopback address, which serves the relay's calls.
    private var blindRelay: RelayOnPhone?
    private var relayListener: (listener: MemberListener, port: UInt16)?
    /// This phone's TLS identity, for the hub's listeners.
    private var memberIdentity: SecIdentity?
    /// Whether the app is in front: the phone is the hub only then (iOS
    /// gives an app no way to keep it running in the background).
    private var foreground = false
    /// The network the phone is on, as the hub remembers home networks.
    private var network: String?
    private let paths = NWPathMonitor()
    /// The hub's changes, one after another.
    private var hubWork: Task<Void, Never>?
    private var online: Set<String> = []
    /// The admin keys the connected computers offer, by device ID.
    private var offers: [String: Data] = [:]
    /// Where the connected members' hellos say their keys live.
    private var keyStores: [String: String] = [:]
    /// What the connected members' hellos say about their devices.
    private var infos: [String: Member.DeviceInfo] = [:]
    /// The sync modes the connected members' hellos report.
    private var modes: [String: String] = [:]
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
    private var authorized: (context: LAContext, at: Date)?

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
        paths.start(queue: DispatchQueue(label: "clipboardbridge.paths"))
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

    /// Whether this phone may add and remove devices: it made the group, or
    /// the phone that did made it an admin. A phone without a group makes
    /// one when it adds a computer.
    var isAdmin: Bool { state?.isAdmin ?? true }
    var isRoot: Bool { state?.isRoot ?? false }
    var alerts: [GroupAlert] { state?.records.alerts ?? [] }

    /// The label of the key this phone signs with: the root key, or the
    /// admin key of a phone that joined.
    nonisolated static func signingLabel(_ g: PhoneGroup?) -> String { g?.isRoot == false ? adminLabel : caLabel }

    var computers: [AppModel.Computer] {
        devices.filter { !$0.isSelf }
    }

    var devices: [AppModel.Computer] {
        guard let g = state else { return [] }
        let root = g.records.rootDevice
        return g.devices.map {
            .init(id: $0.id, name: $0.name, online: $0.id == g.device || online.contains($0.id), role: $0.role, os: $0.os,
                  isSelf: $0.id == g.device,
                  admin: $0.admin || $0.id == root, isRoot: $0.id == root,
                  canMakeAdmin: g.isRoot && !$0.admin && !$0.frozen && $0.role == "full" && offers[$0.id] != nil,
                  keysInFile: Records.store(keyStores[$0.id] ?? $0.store, role: $0.role) == Records.file,
                  rootless: Records.store(keyStores[$0.id] ?? $0.store, role: $0.role) == Records.rootless, frozen: $0.frozen,
                  device: $0.id == g.device ? Self.ownDevice : infos[$0.id], mode: $0.id == g.device ? modeBox.mode : modes[$0.id],
                  actions: actions[$0.id] ?? [])
        }
    }

    func refresh() async {
        online = await node?.connected ?? []
        infos = await node?.devices ?? [:]
        modes = await node?.modes ?? [:]
        actions = await node?.actions ?? [:]
        offers = await node?.offeredAdminKeys ?? [:]
        keyStores = await node?.keyStores ?? [:]
        await finishTakeOverIfDue()
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
        if let a = authorized, Date().timeIntervalSince(a.at) < Self.authorizedFor {
            context = a.context
        } else {
            context = LAContext()
            try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
            authorized = (context, Date())
            renewer?.context = context
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

    private func identity(_ g: PhoneGroup, _ member: SecKeySigner) throws -> SecIdentity {
        try identity(certificate: g.memberCert, member)
    }

    private func identity(certificate: Data, _ member: SecKeySigner) throws -> SecIdentity {
        KeychainIdentity.removeCertificates(label: Self.memberLabel)
        return try KeychainIdentity.identity(certificate: certificate, key: member.key, label: Self.memberLabel, storeKey: false)
    }

    /// The certificates this phone sends after its own in TLS: the admin CA
    /// that issued it, if one did.
    private static func chain(_ g: PhoneGroup) -> [Data] { g.memberIssuer.map { [$0] } ?? [] }

    // MARK: Admitting

    func admit(_ code: JoinCode) async throws {
        let ca = try await caSigner(reason: String(localized: "Add a computer to your group", bundle: .app))
        let member = try memberSigner()
        let made = state == nil
        var g = try state ?? PhoneGroup.create(caSigner: ca, memberKey: member.publicKeyDER, name: UIDevice.current.name,
                                               seal: Self.sealKey(), now: Date())
        let id = try identity(g, member)
        var failure: Error?
        for addr in Self.ordered(code.addrs) {
            try Task.checkCancellation()
            guard let (host, port) = Self.split(addr) else { continue }
            let tls = TLSTransport(host: host, port: port, alpn: Pairing.alpn, identity: id, chain: Self.chain(g)) { leaf in
                Pairing.fingerprint(cert: leaf) == code.fingerprint
            }
            // Closing the connection ends a pairing that takes too long or
            // that the user cancelled: the pending read fails.
            let deadline = Task {
                try await Task.sleep(for: Self.pairingDeadline)
                tls.close()
            }
            defer { deadline.cancel() }
            do {
                let admitted = try await withTaskCancellationHandler {
                    try await tls.start()
                    defer { tls.close() }
                    guard let leaf = tls.peerCertificate,
                          let sid = tls.exportKeyingMaterial(label: Pairing.exporterLabel, length: 32) else { throw Failure.unreachable }
                    // The address that answered goes first, for dialing when mDNS does not find the computer.
                    return try await g.admit(over: tls, code: code.code, joinerCert: leaf, sessionID: sid, caSigner: ca,
                                             addrs: [addr] + code.addrs.filter { $0 != addr }, now: Date())
                } onCancel: {
                    tls.close()
                }
                try g.save(to: file)
                if made { try modeBox.newDevice(); forgetCredentials() }
                state = g
                try startSync()
                groupChanged()
                // A group made on this phone has it as its hub from the start (D-64).
                if made { try? await setPhoneHub(true) }
                await node?.sendRecords(g.records.records)
                guard admitted.confirmed else { throw Failure.notConfirmed }
                return
            } catch let e as PairingMember.Failure {
                throw e // the computer answered: a wrong code is not worth another address
            } catch {
                tls.close()
                if Task.isCancelled { throw CancellationError() }
                failure = Self.telling(failure, error)
            }
        }
        throw failure ?? Failure.unreachable
    }

    /// Of two failures on different addresses, the one that says more: an
    /// address that answered, as with a failed handshake, over one that
    /// did not.
    nonisolated static func telling(_ earlier: Error?, _ later: Error) -> Error {
        guard let earlier else { return later }
        if case TLSTransport.Failure.timedOut = earlier, !isTimeout(later) { return later }
        return earlier
    }

    nonisolated private static func isTimeout(_ e: Error) -> Bool {
        if case TLSTransport.Failure.timedOut = e { return true }
        return false
    }

    /// The addresses to try, IPv4 first: a home network reaches those most
    /// surely, and each that fails costs its timeout.
    nonisolated static func ordered(_ addrs: [String]) -> [String] { JoinCode.ordered(addrs) }

    /// host and port of "host:port" or "[IPv6]:port".
    nonisolated static func split(_ addr: String) -> (String, UInt16)? { JoinCode.split(addr) }

    // MARK: Inviting from afar

    /// Opens a remote invitation on this phone, the group's hub
    /// (docs/protocol.md, section 12): a guest tunnel through the hub's
    /// forwarder and its pairing window, for one device, for lifetime
    /// seconds. ask asks the user whether to admit a device that proved it
    /// knows the secret; on yes Face ID unlocks the group's key. ended gets
    /// the admitted device's name, or why the invitation ended without one.
    func invite(lifetime: Int, ask: @escaping @MainActor (PairingMember.Request) async -> Bool,
                ended: @escaping @MainActor (Result<String, Error>) -> Void) async throws -> AppModel.Invitation {
        guard let g = state, g.isAdmin else { throw Failure.notAdmin }
        guard let hub, let identity = memberIdentity else { throw HubOnPhone.Failure.notRunning }
        let guestBox = GuestBox()
        let window = try InvitationWindow(identity: identity, expires: Date().addingTimeInterval(TimeInterval(lifetime)), admit: { [weak self] t, joinerCert, sid in
            guard let self, let guest = guestBox.guest else { throw HubOnPhone.Failure.notRunning }
            return try await self.admitInvited(over: t, joinerCert: joinerCert, sessionID: sid, guest: guest, ask: ask)
        }, onEnd: { r in
            if case .failure = r { guestBox.guest?.close() }
            Task { @MainActor in ended(r.map(\.info.name)) }
        }, onError: { error in
            hubLog.error("an attempt with the invitation failed: \(String(reflecting: error), privacy: .public)")
        })
        let port = try await window.start()
        let guest: HubGuest
        do {
            guest = try hub.invite(group: g.tag, lifetime: lifetime, guestPort: port)
        } catch {
            window.close()
            throw error
        }
        guestBox.guest = guest
        return AppModel.Invitation(text: guest.text, expires: guest.expires, cancel: { window.close() })
    }

    /// The guest tunnel, which the window's attempts need once it is open.
    private final class GuestBox: @unchecked Sendable {
        var guest: HubGuest?
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

    /// One attempt with an invitation: the device that proves the secret
    /// and that the user confirms is admitted.
    private func admitInvited(over t: TLSTransport, joinerCert: Data, sessionID: [UInt8], guest: HubGuest,
                              ask: @escaping @MainActor (PairingMember.Request) async -> Bool) async throws -> PairingMember.Admitted {
        guard var g = state else { throw Failure.notAdmin }
        let unlocked = UnlockedSigner()
        let reason = String(localized: "Add a computer to your group", bundle: .app)
        let invitation = PairingMember.Invitation(secret: guest.secret) { [weak self] req in
            // The device waits up to 5 minutes for the answer.
            guard await ask(req), let self else { return false }
            do {
                let ca = try await self.caSigner(reason: reason)
                await MainActor.run { unlocked.signer = ca }
                return true
            } catch {
                return false
            }
        }
        let admitted = try await g.admit(over: t, code: "", joinerCert: joinerCert, sessionID: sessionID, caSigner: unlocked,
                                         invitation: invitation, now: Date())
        guest.admitted()
        try g.save(to: file)
        state = g
        groupChanged()
        await node?.sendRecords(g.records.records)
        return admitted
    }

    // MARK: Joining

    /// Joins another phone's group (docs/protocol.md, section 6, "The
    /// joiner listens"): makes this phone's admin key, listens, hands show
    /// the QR code to put on screen, and waits up to five minutes for an
    /// admin phone to scan it and admit this one. Three wrong codes end it,
    /// as does cancelling the task.
    func join(show: @escaping @MainActor (JoinCode) -> Void) async throws {
        guard state == nil else { return }
        let member = try memberSigner()
        // The admin key, in the Secure Enclave behind Face ID like the root
        // key; reading its public key asks for nothing.
        let se = Self.secureEnclave
        let admin = try SecKeySigner(KeychainIdentity.loadKey(label: Self.adminLabel)
            ?? KeychainIdentity.makeKey(label: Self.adminLabel, secureEnclave: se, userPresence: se))
        let device = SyncEngine.newID()
        let cert = try GroupCertificates.selfSigned(device: device, signer: member)
        let id = try identity(certificate: cert, member)
        let listener = try TLSListener(alpn: Pairing.alpn, identity: id) { !$0.isEmpty }
        let port = try await listener.start()
        let addrs = LocalAddresses.current().map { JoinCode.address(host: $0, port: port) }
        guard !addrs.isEmpty else {
            listener.stop()
            throw Failure.noNetwork
        }
        let code = JoinCode(code: JoinCode.newCode(), addrs: addrs, fingerprint: Pairing.fingerprint(cert: cert))
        show(code)
        let info = Pairing.Info(name: PhoneGroup.validName(UIDevice.current.name), os: "ios", adminKey: admin.publicKeyDER,
                                seal: Self.sealKey())
        let file = file
        let timer = Task {
            try await Task.sleep(for: .seconds(Self.joinWindow))
            listener.stop()
        }
        defer {
            timer.cancel()
            listener.stop()
        }
        var wrong = 0
        let joined: PairingJoiner.Joined? = try await withTaskCancellationHandler {
            while let t = await listener.next() {
                do {
                    try await t.start()
                    defer { t.close() }
                    guard let leaf = t.peerCertificate, let sid = t.exportKeyingMaterial(label: Pairing.exporterLabel, length: 32) else { continue }
                    return try await PairingJoiner.accept(over: t, code: code.code, info: info, memberCert: leaf, joinerCert: cert,
                                                          sessionID: sid, now: Date()) { try PhoneGroup.joined($0).save(to: file) }
                } catch PairingJoiner.Failure.refused(.wrongCode) {
                    wrong += 1
                    if wrong >= Self.joinAttempts { throw Failure.tooManyWrongCodes }
                } catch {
                    continue // another device, or a dropped connection: the code is not spent
                }
            }
            return nil
        } onCancel: {
            listener.stop()
        }
        guard let joined else {
            if Task.isCancelled { throw CancellationError() }
            throw Failure.timedOut
        }
        try modeBox.newDevice()
        forgetCredentials()
        state = PhoneGroup.joined(joined)
        try startSync()
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
        await node?.sendRecords([r])
        await node?.close(peer: id)
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
        await node?.sendRecords([r])
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
        await node?.sendRecords([r])
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
            await node?.sendRecords([r])
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
        await node?.sendRecords([r])
    }

    /// Sets the sync mode of a connected computer (docs/protocol.md, section
    /// 15): a command signed with this phone's root or admin key after Face
    /// ID, which only that computer takes, within 30 s.
    func setMode(_ id: String, to mode: String) async throws {
        if id == state?.device {
            try modeBox.set(mode)
            await node?.set(mode: mode)
            return
        }
        guard let node else { throw MemberNode.Failure.notConnected }
        let ca = try await caSigner(reason: String(localized: "Change a computer's sync mode", bundle: .app))
        guard let g = state else { return }
        let c = try g.modeCommand(to: id, mode: mode, caSigner: ca, now: Date())
        let r = try await node.command(c, to: id)
        if !r.done { throw CommandRefused(reason: r.reason ?? r.status) }
    }

    /// Puts text where the focus of a computer is (design.md, "Remote
    /// paste"): a paste command signed with this phone's root or admin key
    /// after Face ID, passed on by a hub of the group connected to it when this phone
    /// is not; the computer answers once the text is in, or why not.
    func paste(_ id: String, text: String, method: String, enter: Bool, secret: Bool) async throws {
        guard let node else { throw MemberNode.Failure.notConnected }
        let ca = try await caSigner(reason: String(localized: "Paste on a device", bundle: .app))
        guard let g = state else { return }
        let c = try g.pasteCommand(to: id, text: text, method: method, enter: enter, secret: secret, caSigner: ca, now: Date())
        // The computer waits 5 s for its target, and 5 ms more for each typed byte.
        let wait = 10 + (method == "type" ? Double(text.utf8.count) * 0.005 : 0)
        let r = try await node.command(c, to: id, timeout: wait, via: g.records.hubOrder)
        if !r.done { throw CommandRefused(reason: r.reason ?? r.status) }
    }

    /// Runs a quick action on a device (docs/protocol.md, section 15): an
    /// action command, signed with this phone's root or admin key after Face
    /// ID, names it; the device defines what it does and runs it only when
    /// its user turned it on there.
    func runAction(_ id: String, name: String) async throws {
        guard let node else { throw MemberNode.Failure.notConnected }
        let ca = try await caSigner(reason: String(localized: "Run a quick action", bundle: .app))
        guard let g = state else { return }
        let c = try g.actionCommand(to: id, name: name, caSigner: ca, now: Date())
        // A preset may take 20 s to start, and an own action runs up to 15 s.
        let r = try await node.command(c, to: id, timeout: 25, via: g.records.hubOrder)
        if !r.done { throw CommandRefused(reason: r.reason ?? r.status) }
    }

    /// Turns every quick action off on a device; only its user turns them
    /// on again.
    func actionsOff(_ id: String) async throws {
        guard let node else { throw MemberNode.Failure.notConnected }
        let ca = try await caSigner(reason: String(localized: "Run a quick action", bundle: .app))
        guard let g = state else { return }
        let c = try g.actionsOffCommand(to: id, caSigner: ca, now: Date())
        let r = try await node.command(c, to: id, via: g.records.hubOrder)
        if !r.done { throw CommandRefused(reason: r.reason ?? r.status) }
    }

    /// Makes a computer an admin (docs/protocol.md, section 10, "A computer
    /// as admin"): the root key, after Face ID, certifies the admin key the
    /// computer offers; the computer gets its admin CA and every member the
    /// new record.
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
        await node?.sendRecords([r])
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
            await node?.sendRecords([r])
            return
        }
        guard let to = o?["to"] as? String else { throw PhoneGroup.Failure.notForWatch }
        guard let node else { throw MemberNode.Failure.notConnected }
        let res = try await node.command(r, to: to, timeout: 25, via: state?.records.hubOrder ?? [])
        if !res.done { throw CommandRefused(reason: res.reason ?? res.status) }
    }

    /// Makes a computer an admin; one whose keys sit in a file only with
    /// allowFileKey, else PhoneGroup.Failure.fileKey; a rootless install
    /// never (PhoneGroup.Failure.rootless).
    private func makeAdmin(_ id: String, allowFileKey: Bool) async throws {
        guard state?.isRoot == true, let key = offers[id] else { throw Failure.notAdmin }
        let store = keyStores[id]
        guard Records.store(store, role: "full") != Records.rootless else { throw PhoneGroup.Failure.rootless }
        guard Records.store(store, role: "full") == Records.hardware || allowFileKey else { throw PhoneGroup.Failure.fileKey }
        let root = try await caSigner(reason: String(localized: "Make a computer an admin", bundle: .app))
        guard var g = state else { return }
        let (ca, r) = try g.makeAdmin(device: id, adminKey: key, rootSigner: root, now: Date(), keyStore: store, allowFileKey: allowFileKey)
        try g.save(to: file)
        state = g
        groupChanged()
        await node?.sendRecords([r])
        await node?.send(adminCA: ca, to: id)
    }

    /// Removes the phone that holds the group's root, when it is lost: this
    /// admin phone makes a new root key in the Secure Enclave, behind Face
    /// ID, and claims the group for it (docs/protocol.md, section 10, "Handing the
    /// group over"). The claim waits the group's delay, in which the root,
    /// if it is still in use, cancels it; finishTakeOverIfDue then makes
    /// this phone the root.
    private func takeOver(from id: String) async throws {
        let reason = String(localized: "Take the group over from the lost phone", bundle: .app)
        let admin = try await signer(label: Self.adminLabel, reason: reason)
        // A root key left from a group this phone made before goes.
        KeychainIdentity.removeKey(label: Self.caLabel)
        let se = Self.secureEnclave
        _ = try KeychainIdentity.makeKey(label: Self.caLabel, secureEnclave: se, userPresence: se)
        let root = try await signer(label: Self.caLabel, reason: reason)
        guard var g = state else { return }
        let newRoot = try GroupCertificates.groupCA(signer: root, now: Date(), pathLength: 1)
        let r = try g.takeOver(from: id, adminSigner: admin, newRoot: newRoot, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        await node?.sendRecords([r])
    }

    /// Makes this phone the group's root once its claim took effect: it
    /// signs, with the new root key, what a new root starts with, and
    /// becomes the hub when the lost phone was (docs/design.md, "Losing the
    /// phone"). A claim that was cancelled is dropped.
    private func finishTakeOverIfDue() async {
        guard var g = state, g.claim != nil else { return }
        g.records.refresh()
        g.adoptRoots()
        let lost = g.claimedFrom
        if g.currentRoot != g.claim {
            guard g.dropEndedClaim() else { return }
            keysLog.notice("the claim to take the group over ended; this phone stays an admin")
            try? g.save(to: file)
            state = g
            return
        }
        do {
            let root = try await signer(label: Self.caLabel, reason: String(localized: "Take the group over from the lost phone", bundle: .app))
            guard var g = state else { return }
            let rs = try g.finishTakeOver(rootSigner: root, now: Date())
            try g.save(to: file)
            state = g
            groupChanged()
            await node?.sendRecords(rs)
            if let lost { await node?.close(peer: lost) }
            if let lost, await away?.hub == lost {
                try await setPhoneHub(true)
            } else {
                await restartSync()
            }
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

    /// Drops the credentials and the keys for the servers of an earlier
    /// group, when the phone makes or joins one.
    private func forgetCredentials() {
        try? FileManager.default.removeItem(at: credentialsURL)
        periodKeys.clear()
        blindRelay?.setCredentials(nil)
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
        if !signed.isEmpty { Task { await node.sendCredentials(signed) } }
        blindRelay?.setCredentials(box.relayCredentials(keys: periodKeys))
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
        hubRecords(g)
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
        relay?.allowed = Self.allowed(g)
        credentialBox?.group = g
        refreshCredentials()
        hubRecords(g)
        if g.roots != roots { Task { await restartSync() } }
    }

    // MARK: Syncing

    /// Starts finding and dialing the computers, once there is a group.
    private func startSync() throws {
        guard let g = state, node == nil else { return }
        let id = try identity(g, memberSigner())
        let box = RecordBox(groupCA: g.groupCA, set: g.records)
        box.onAdd = { [weak self] set in Task { @MainActor in self?.adopt(set) } }
        let credentials = CredentialBox(url: credentialsURL, group: g)
        credentials.onAdd = { [weak self] in Task { @MainActor in self?.refreshCredentials() } }
        // An admin phone renews the computers' certificates when they
        // connect and are due (docs/protocol.md, section 2).
        let renewer = Renewer(group: g, secureEnclave: Self.secureEnclave)
        renewer.context = authorized?.context
        // The root sends a computer it made an admin its admin CA again
        // when the computer still offers the key.
        let admins = AdminBox(group: g)
        // Sync away from home: the hellos offer the tunnel key while it is
        // on, and the hub's answer goes to AwayFromHome.
        let awayState = AwayKeychain.load()
        let awayRef = Ref<AwayFromHome>()
        // The phone as the hub answers the tunnel keys of the hellos, shares
        // its clients with the group's other hubs and passes their offers
        // on; it is no client itself (D-64; docs/protocol.md, section 11,
        // "Several hubs").
        let hub = HubOnPhone(device: g.device, tunnels: GoHubTunnels(), state: HubKeychain.load(), save: { try HubKeychain.save($0) },
                             log: { what, error in hubLog.error("\(what, privacy: .public): \(error.map { String(reflecting: $0) } ?? "", privacy: .public)") })
        let isHub = g.isAdmin && hub.isOn
        var answer: (@Sendable (String, Data, Data?, [Data]) -> [Member.TunnelOffer])?
        var sharing: (@Sendable (String, [Data]) -> Member.HubShare?)?
        let nodeRef = Ref<MemberNode>()
        if isHub {
            let share: @Sendable (String, [Data]) -> Member.HubShare? = { peer, chain in box.mayHost(peer, chain: chain) ? hub.share() : nil }
            answer = { device, key, psk, _ in
                // A client admitted now is shared with the other hubs at
                // once, so that it reaches them when this phone is off.
                hub.offers(device: device, key: key, psk: psk, order: box.hubOrder,
                           admitted: { Task { await nodeRef.value?.sendHubs(share) } })
            }
            sharing = share
        }
        let offered: Data? = isHub ? nil : awayState.flatMap { try? GoTunnels().publicKey($0.key) }
        let modeBox = modeBox, device = g.device, recent = Self.recentCopyMS
        let node = MemberNode(engine: SyncEngine(device: g.device, clock: HybridClock()), name: UIDevice.current.name, os: "ios",
                              device: Self.ownDevice, records: box, renew: { renewer.renew($0) }, adminCA: { admins.group.computerAdminCA(for: $0) },
                              tunnelKey: offered, tunnelPSK: offered == nil ? nil : awayState?.psk, hub: answer, hubShare: sharing,
                              // A copy of a moment ago from another device, in a sync
                              // mode that takes the group's copies, while the app runs.
                              onChange: { [weak self] e in
                                  guard Member.receives(modeBox.mode), !e.isMark, e.origin != device, e.ageMS < recent else { return }
                                  if let part = Images.part(of: e.media) {
                                      Task { @MainActor in
                                          do {
                                              try await self?.receive(e, image: part)
                                          } catch {
                                              imageLog.error("fetching an image: \(String(reflecting: error), privacy: .public)")
                                          }
                                      }
                                  } else if !e.text.isEmpty {
                                      Task { @MainActor in self?.write(e.text, kind: e.kind) }
                                  }
                              },
                              onTunnel: { from, offer in Task { await awayRef.value?.keep(from: from, offer: offer) } },
                              onHubs: { from, _, share in
                                  guard isHub else {
                                      // A client keeps the sharing hub's offer with its own preshared key, as any hub's.
                                      guard let o = share.offer else { return }
                                      Task {
                                          guard let away = awayRef.value, let psk = await away.psk else { return }
                                          await away.keep(from: from, offer: o.with(psk: psk, hub: nil))
                                      }
                                      return
                                  }
                                  guard hub.shared(from: from, share, known: { box.knows($0) }) else { return }
                                  Task { await nodeRef.value?.sendTunnels { hub.offers(for: $0, order: box.hubOrder) } }
                              },
                              mode: modeBox.mode,
                              onCommand: { [weak self] peer, c in
                                  let (result, change) = modeBox.take(c, from: peer, records: box, me: device)
                                  switch change {
                                  case let .mode(mode)?: Task { await nodeRef.value?.set(mode: mode) }
                                  case .awayOff?:
                                      // Connects again once the result has gone back on the
                                      // connection that brought the command.
                                      Task { @MainActor in
                                          try? await Task.sleep(for: .milliseconds(500))
                                          do { try await self?.setAwayFromHome(false) } catch {
                                              modeLog.error("cannot turn sync away from home off: \(String(reflecting: error), privacy: .public)")
                                          }
                                      }
                                  case nil: break
                                  }
                                  return result
                              },
                              onEvidence: { [weak self] peer, chain, e in
                                  Task { @MainActor in await self?.evidenceReceived(from: peer, chain: chain, e) }
                              },
                              content: content, credentials: credentials)
        nodeRef.value = node
        let relay = Relay(group: g.tag)
        relay.allowed = Self.allowed(g)
        // Through the tunnel the phone dials the hub's member port with the
        // same TLS as at home, and only while the hub is not found here.
        let chain = Self.chain(g), roots = g.trusted
        let away = AwayFromHome(
            device: g.device, tunnels: GoTunnels(), state: awayState, save: { try AwayKeychain.save($0) },
            atHome: { hub in await relay.atHome(hub) },
            dial: { port, hub in
                let t = TLSTransport(endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port) ?? .any),
                                     alpn: Member.alpn, identity: id, chain: chain) { peer in
                    (try? GroupCertificates.verifyMember(chain: peer, roots: roots, now: Date())) == hub
                }
                try await t.start()
                return t
            },
            serve: { t, hub in try await node.serve(t, peer: hub) },
            mayHost: { box.mayHost($0) },
            order: { box.hubOrder },
            log: { what, error in awayLog.error("\(what, privacy: .public): \(String(reflecting: error), privacy: .public)") },
            isPhone: { box.isPhone($0) })
        awayRef.value = away
        Task { await away.start() }
        // At a blind relay the phone dials the device the relay joined, with
        // the same TLS as at home, while it is not found here.
        let blindRelay = RelayOnPhone(
            device: g.device, links: GoRelayLinks(), settings: RelayKeychain.load(), save: { try RelayKeychain.save($0) },
            dial: { port, peer in
                let t = TLSTransport(endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port) ?? .any),
                                     alpn: Member.alpn, identity: id, chain: chain) { c in
                    (try? GroupCertificates.verifyMember(chain: c, roots: roots, now: Date())) == peer
                }
                try await t.start()
                return t
            },
            serve: { t, peer in try await node.serve(t, peer: peer) },
            elsewhere: { relay.found($0) },
            log: { what, error in relayLog.error("\(what, privacy: .public): \(error.map { String(reflecting: $0) } ?? "", privacy: .public)") })
        let browser = BonjourBrowser(log: { browseLog.notice("\($0, privacy: .public)") }) { found in relay.update(found) }
        let dialer = MemberDialer(node: node, group: g.tag,
                                  dial: browser.dialer(identity: id, chain: Self.chain(g), roots: g.trusted) { relay.addresses[$0] ?? [] })
        relay.dialer = dialer
        // The computers at known addresses are dialed even while browsing finds nothing.
        relay.addresses = g.addresses
        browser.start()
        (self.node, self.browser, self.dialer, self.relay, self.recordBox, self.renewer, self.admins, self.away) =
            (node, browser, dialer, relay, box, renewer, admins, away)
        (self.hub, self.blindRelay, memberIdentity, credentialBox) = (hub, blindRelay, id, credentials)
        refreshHub()
        refreshCredentials()
    }

    /// Stops syncing and starts again, with a renewed certificate.
    private func restartSync() async {
        await hubDone()
        stopHub()
        stopRelay()
        (hub, blindRelay) = (nil, nil)
        await away?.stop()
        await dialer?.stop()
        browser?.stop()
        await node?.closeAll()
        (node, browser, dialer, relay, recordBox, renewer, admins, away) = (nil, nil, nil, nil, nil, nil, nil, nil)
        credentialBox = nil
        try? startSync()
    }

    // MARK: The phone as the hub

    /// The phone as the group's hub as Settings shows it: nil without a
    /// group, or on a phone that is no admin, which cannot be the hub.
    func hubStatus() async -> AppModel.Hub? {
        guard let hub, state?.isAdmin == true else { return nil }
        let (status, error) = hub.status(paused: !foreground)
        var h = AppModel.Hub(on: hub.isOn, status: status, error: error, forwarder: hub.forwarder,
                             home: hub.isHome(network), clients: hub.clients.count)
        // The computers show without a forwarder too, so that the user sees
        // where the hub can go; Settings asks for the forwarder first.
        if hub.isOn {
            let movable = computers.filter { $0.online && $0.role == "full" && ($0.admin || $0.canMakeAdmin) }
            h.computers = movable.map { .init(id: $0.id, name: $0.name) }
            if !UserDefaults.standard.bool(forKey: Self.keepsPhoneHubKey),
               let s = movable.first(where: { Self.alwaysOn.contains($0.device?.form ?? "") }) {
                h.suggested = .init(id: s.id, name: s.name)
            }
        }
        return h
    }

    /// The default that records the user's choice to keep this phone as
    /// the hub when the app suggested a computer (docs/design.md, "Moving
    /// the hub to a computer").
    static let keepsPhoneHubKey = "KeepsPhoneHub"

    /// The longest the old hub waits for its clients' connections to end
    /// after it passed the new hub's offer on.
    static let moveGrace: Duration = .seconds(10)

    /// The forms of devices that are always on, as their hellos state them.
    private static let alwaysOn: Set<String> = ["desktop", "server", "board", "router"]

    /// Makes a connected admin computer the group's hub in place of this
    /// phone (docs/protocol.md, section 11, "Moving the hub"): a hub command
    /// signed with this phone's root or admin key after Face ID hands it the
    /// clients' keys and the forwarder; the clients connected now get its
    /// offer from this phone, which then stops being the hub and becomes
    /// its client. A computer that is no admin yet becomes one first, on
    /// the root.
    func moveHub(to id: String) async throws {
        guard let hub, hub.isOn, let fw = hub.forwarder else { throw HubOnPhone.Failure.notRunning }
        guard let node else { throw MemberNode.Failure.notConnected }
        if state?.records.mayHost(id) != true { try await makeAdmin(id, allowFileKey: false) }
        let ca = try await caSigner(reason: String(localized: "Move the hub to a computer", bundle: .app))
        guard let g = state, let away else { return }
        // This phone is the new hub's client from now on, with a key of its own.
        let wasOn = await away.isOn
        if !wasOn { try await away.turnOn() }
        guard let key = await away.publicKey, let psk = await away.psk else { throw HubOnPhone.Failure.notRunning }
        let clients = hub.handover + [PhoneHub.Client(device: g.device, key: key, psk: psk)]
        let offer: Member.TunnelOffer
        do {
            let c = try g.hubCommand(to: id, forwarder: (fw.endpoint, fw.pin), clients: clients, caSigner: ca, now: Date())
            let r = try await node.command(c, to: id, timeout: 20)
            guard r.done, let o = r.tunnel else { throw CommandRefused(reason: r.reason ?? r.status) }
            offer = o
        } catch {
            if !wasOn { try? await away.turnOff() }
            throw error
        }
        let sent = await node.sendTunnel { hub.movedOffer(device: $0, newHub: id, offer: offer) }
        // The clients that came through the tunnel get the offer before it
        // closes: each connection ends after the offer and a goodbye, and
        // the last packets get a second more.
        await node.sayGoodbye(to: sent, timeout: Self.moveGrace)
        try? await Task.sleep(for: .seconds(1))
        try hub.turnOff()
        await away.keep(from: id, offer: offer.with(psk: psk, hub: nil))
        await restartSync()
    }

    /// Tells the group the app came to the front or went to the background;
    /// the hub follows.
    func setForeground(_ on: Bool) {
        foreground = on
        refreshHub()
        // Back at the front without a computer: iOS may have ended the
        // browsing in the background, so it starts again.
        if on, let node, let browser {
            let dialer = dialer
            Task {
                if await node.connected.isEmpty {
                    browser.restart()
                    await dialer?.hurry()
                }
            }
        }
    }

    /// Makes this phone the group's hub, or stops it being the hub. A hub
    /// is no client of another, so turning it on turns this phone's own
    /// sync away from home off; then it connects again, so the hellos it
    /// answers get its offers.
    func setPhoneHub(_ on: Bool) async throws {
        guard let hub, state?.isAdmin == true else { return }
        if on {
            if await away?.isOn == true { try await away?.turnOff() }
            try hub.turnOn(home: network)
        } else {
            try hub.turnOff()
        }
        await restartSync()
    }

    /// Sets the hub's forwarder, or none for a hub at home only.
    func setForwarder(address: String, pin: String) async throws {
        guard let hub else { return }
        let a = address.trimmingCharacters(in: .whitespaces), p = pin.trimmingCharacters(in: .whitespaces)
        if a.isEmpty && p.isEmpty {
            try hub.setForwarder(nil)
        } else {
            guard let ep = HubState.endpoint(a) else { throw HubOnPhone.Failure.badForwarder }
            try hub.setForwarder(.init(endpoint: ep, pin: p))
        }
        refreshHub()
    }

    /// Remembers the network the phone is on as a home network, where the
    /// hub takes members and publishes itself.
    func addHomeNetwork() async throws {
        guard let hub, let network else { return }
        try hub.addHome(network)
        refreshHub()
    }

    /// Runs updateHub after the changes before it.
    private func refreshHub() {
        let previous = hubWork
        hubWork = Task { @MainActor [weak self] in
            await previous?.value
            await self?.updateHub()
            await self?.updateRelay()
        }
    }

    private func hubDone() async { await hubWork?.value }

    /// Runs the hub's parts that the moment calls for: with the hub on and
    /// the app in front, the member listener on the loopback address and
    /// the tunnel with its registration; on a home network besides, the
    /// member listener there, published by Bonjour. Otherwise it stops
    /// them.
    private func updateHub() async {
        guard let hub, let node, let g = state, let id = memberIdentity, g.isAdmin, hub.isOn, foreground,
              let member = try? memberSigner() else { return stopHub() }
        let roots = g.trusted, chain = Self.chain(g)
        let onError: @Sendable (Error) -> Void = { hubLog.error("a member connection to the hub failed: \(String(reflecting: $0), privacy: .public)") }
        if tunnelListener == nil {
            do {
                let l = try MemberListener(node: node, identity: id, chain: chain, trusted: { roots }, onError: onError)
                tunnelListener = (l, try await l.start())
            } catch {
                hubLog.error("the hub cannot listen: \(String(reflecting: error), privacy: .public)")
                return
            }
        }
        guard let port = tunnelListener?.port, self.hub === hub else { return }
        let sign: @Sendable (Data) throws -> Data = { try member.signature(digest: $0) }
        // The forwarder takes the member chain and the group's roots after it (docs/protocol.md, section 13).
        hub.start(.init(memberPort: port, chain: g.memberChain + roots, sign: sign, records: g.records.authorityRecords))
        guard hub.isHome(network) else {
            homeListener?.stop()
            homeListener = nil
            return
        }
        guard homeListener == nil else { return }
        let service = (name: g.device, txt: ["v": "1", "g": g.tag, "r": "phone"])
        for p in [Self.memberPort, 0] {
            guard let l = try? MemberListener(node: node, identity: id, chain: chain, trusted: { roots }, port: p, loopback: false,
                                              service: service, onError: onError) else { continue }
            if (try? await l.start()) != nil {
                homeListener = l
                return
            }
        }
        hubLog.error("the hub cannot listen on the home network")
    }

    private func stopHub() {
        homeListener?.stop()
        tunnelListener?.listener.stop()
        (homeListener, tunnelListener) = (nil, nil)
        hub?.stop()
    }

    /// Forgets the hub's clients the records removed and hands its
    /// forwarder the new authority records.
    private func hubRecords(_ g: PhoneGroup) {
        guard let hub else { return }
        let ids = Set(g.devices.map(\.id))
        hub.prune { ids.contains($0) }
        hub.setRecords(g.records.authorityRecords)
        blindRelay?.setRecords(g.records.authorityRecords)
    }

    // MARK: The blind relay

    /// Runs the link to the blind relay while it is on and the app is in
    /// front, with its member listener on the loopback address, which
    /// serves only the calls the relay announced and only when the
    /// certificate names the caller; otherwise it stops them.
    private func updateRelay() async {
        guard let r = blindRelay, let node, let g = state, let id = memberIdentity, r.isOn, foreground,
              let member = try? memberSigner() else { return stopRelay() }
        if relayListener == nil {
            let roots = g.trusted
            do {
                let l = try MemberListener(node: node, identity: id, chain: Self.chain(g), trusted: { roots }, caller: { r.caller(port: $0) },
                                           onError: { relayLog.error("a call through the relay failed: \(String(reflecting: $0), privacy: .public)") })
                relayListener = (l, try await l.start())
            } catch {
                relayLog.error("the relay's calls cannot be taken: \(String(reflecting: error), privacy: .public)")
                return
            }
        }
        guard let port = relayListener?.port, blindRelay === r else { return }
        let sign: @Sendable (Data) throws -> Data = { try member.signature(digest: $0) }
        // The relay takes the member chain and the group's roots after it, as a forwarder (docs/protocol.md, section 14).
        r.start(.init(memberPort: port, chain: g.memberChain + g.trusted, sign: sign, records: g.records.authorityRecords))
        r.setCredentials(credentialBox?.relayCredentials(keys: periodKeys))
    }

    private func stopRelay() {
        relayListener?.listener.stop()
        relayListener = nil
        blindRelay?.stop()
    }

    /// The blind relay as Settings shows it; nil without a group.
    func relayStatus() async -> AppModel.BlindRelay? {
        guard let r = blindRelay else { return nil }
        let (status, report, error) = r.status(paused: !foreground)
        return AppModel.BlindRelay(status: status, error: error, relay: r.relay, online: report.online.count, through: report.through)
    }

    /// Meets the group at the relay at address, whose key is pin, after the
    /// user read what a relay learns; both empty leave it.
    func setRelay(address: String, pin: String) async throws {
        guard let r = blindRelay else { return }
        let a = address.trimmingCharacters(in: .whitespaces), p = pin.trimmingCharacters(in: .whitespaces)
        if a.isEmpty && p.isEmpty {
            try r.turnOff()
        } else {
            try r.turnOn(endpoint: a, pin: p)
        }
        refreshHub()
    }

    /// The member port the hub takes members on at home, as the computers';
    /// another when it is taken.
    static let memberPort: UInt16 = 8764

    /// Sync away from home as Settings shows it; nil without a group.
    func awayStatus() async -> (on: Bool, status: AwayFromHome.Status, error: Error?)? {
        guard let away else { return nil }
        return (await away.isOn, await away.status, await away.lastError)
    }

    /// Turns sync away from home on or off, then connects again, so the
    /// hellos offer the new key and the hub answers it.
    func setAwayFromHome(_ on: Bool) async throws {
        guard let away else { return }
        if on { try await away.turnOn() } else { try await away.turnOff() }
        await restartSync()
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

    /// Issues renewed member certificates with the root or admin key, without
    /// asking: in the Secure Enclave only while the context of the user's
    /// last Face ID check in this run lasts, so a computer that is due and
    /// connects before that gets its renewal on a later connection.
    final class Renewer: @unchecked Sendable {
        let group: PhoneGroup
        let secureEnclave: Bool
        private let lock = NSLock()
        private var _context: LAContext?
        var context: LAContext? {
            get { lock.withLock { _context } }
            set { lock.withLock { _context = newValue } }
        }

        init(group: PhoneGroup, secureEnclave: Bool) { (self.group, self.secureEnclave) = (group, secureEnclave) }

        /// A renewal for a peer's chain, leaf first, when it is due and this
        /// phone may renew it.
        func renew(_ chain: [Data]) -> MemberNode.Renewal? {
            guard group.isAdmin, let cert = chain.first,
                  GroupCertificates.isDue(cert, groupCA: group.adminCA ?? group.currentRoot, now: Date()),
                  let signer = signer() else { return nil }
            return group.renewal(chain: chain, caSigner: signer, now: Date())
        }

        /// The root or admin key's signer while it signs without asking.
        func signer() -> SecKeySigner? {
            var ctx = context
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
    /// mode beside the group's, as the computers keep it: own for a phone
    /// that makes or joins a group from now on, shared for one that joined
    /// before 0.5, which has no file; and the replay cache of the commands
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

        /// The sync mode: own, shared, receive or send.
        var mode: String {
            lock.withLock {
                let m = (try? String(contentsOf: url, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
                return m.flatMap { Member.modes.contains($0) ? $0 : nil } ?? "shared"
            }
        }

        /// Sets the sync mode and keeps it.
        func set(_ mode: String) throws {
            guard Member.modes.contains(mode) else { throw Commands.Failure.unknownMode(mode) }
            try lock.withLock { try Data((mode + "\n").utf8).write(to: url, options: .atomic) }
        }

        /// Gives a phone that just made or joined a group the sync mode of a
        /// new device, own, unless it has one from an earlier group.
        func newDevice() throws {
            if !FileManager.default.fileExists(atPath: url.path) { try set("own") }
        }

        /// What a command that was taken changes beyond its result: the new
        /// sync mode, or sync away from home turned off.
        enum Change { case mode(String), awayOff }

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
            case "paste-off", "actions-off":
                // This phone takes no remote paste and has no quick
                // actions, so nothing of them stays on.
                return (Member.CommandResult(id: body.id, status: "done"), nil)
            case "paste":
                return refused("this phone takes no remote paste")
            case "action":
                return refused("a phone has no quick actions")
            case "hub":
                return refused("a phone does not become the hub by a command; move the hub from the phone that is the hub")
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

    final class RecordBox: RecordStore, @unchecked Sendable {
        private let lock = NSLock()
        private var set: RecordSet
        let groupCA: Data
        var onAdd: (@Sendable (RecordSet) -> Void)?

        init(groupCA: Data, set: RecordSet) { (self.groupCA, self.set) = (groupCA, set) }

        var digest: String? { lock.withLock { set.digest } }
        var all: [Member.Record] { lock.withLock { set.records } }

        func add(_ rs: [Member.Record]) -> [Member.Record] {
            let (fresh, now): ([Member.Record], RecordSet) = lock.withLock {
                (set.addAll(rs, groupCA: groupCA), set)
            }
            if !fresh.isEmpty { onAdd?(now) }
            return fresh
        }

        func replace(_ new: RecordSet) { lock.withLock { set = new } }

        /// Whether device may be the hub for sync away from home.
        func mayHost(_ device: String) -> Bool { lock.withLock { set.mayHost(device) } }

        func mayHost(_ device: String, chain: [Data]) -> Bool { lock.withLock { set.mayHost(device, chain: chain) } }

        /// The group's hubs, highest first.
        var hubOrder: [String] { lock.withLock { set.hubOrder } }

        /// Whether a record names device.
        func knows(_ device: String) -> Bool { lock.withLock { set.knows(device) } }

        /// Checks a command for me against the records now (Commands.verify),
        /// opening a sealed one with this phone's secret for sealed messages.
        func verify(_ c: Member.Record, me: String, nowMS: Int64) throws -> Commands.Body {
            let secret = try? SealKey.secret()
            return try lock.withLock { try Commands.verify(c, records: set, me: me, nowMS: nowMS, secret: secret) }
        }

        /// Whether device is a phone, a hub only while its app is open.
        func isPhone(_ device: String) -> Bool { lock.withLock { set.devices.first { $0.id == device }?.role == "phone" } }

        func refused(chain: [Data]) -> String? { lock.withLock { set.refused(chain: chain) } }
        func stopped(chain: [Data]) -> Bool { lock.withLock { set.stopped(chain: chain) } }
        func noSecrets(to device: String?) -> Bool { lock.withLock { set.noSecrets(to: device) } }
    }

    /// Passes what the browser finds to the dialer, with the computers it
    /// does not find at the addresses they had when admitted, only the
    /// devices that are in the group's list: a removed computer is not
    /// dialed.
    final class Relay: @unchecked Sendable {
        private let lock = NSLock()
        private var _dialer: MemberDialer?
        private var _allowed: Set<String>? = []
        private var _addresses: [String: [String]] = [:]
        private var last: Set<FoundMember> = []
        private var foundAt: [String: TimeInterval] = [:]
        /// The group tag of the members at known addresses.
        let group: String

        init(group: String) { self.group = group }
        var dialer: MemberDialer? {
            get { lock.withLock { _dialer } }
            set { lock.withLock { _dialer = newValue } }
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
        /// How long a member that the browser finds counts as at home
        /// without a connection to it: anyone on a network can announce a
        /// member's name and the group's tag (docs/protocol.md, section 11).
        static let nearGrace: TimeInterval = 30

        /// Whether the browser finds device on the home network now, and
        /// either found it within nearGrace or the dialer is connected to it.
        func atHome(_ device: String) async -> Bool {
            let (at, d): (TimeInterval?, MemberDialer?) = lock.withLock { (foundAt[device], _dialer) }
            guard let at else { return false }
            if ProcessInfo.processInfo.systemUptime - at < Self.nearGrace { return true }
            return await d?.connected.contains(device) ?? false
        }

        /// Whether the browser finds device on the home network now, where
        /// the dialer reaches it directly.
        func found(_ device: String) -> Bool { lock.withLock { foundAt[device] != nil } }

        func update(_ found: Set<FoundMember>) {
            let (d, members): (MemberDialer?, Set<FoundMember>) = lock.withLock {
                last = found
                let now = ProcessInfo.processInfo.systemUptime
                foundAt = Dictionary(uniqueKeysWithValues: Set(found.filter { $0.group == group }.map(\.device)).map { ($0, foundAt[$0] ?? now) })
                let all = Discovery.withKnown(found, known: Set(_addresses.keys), group: group)
                return (_dialer, _allowed.map { a in all.filter { a.contains($0.device) } } ?? all)
            }
            guard let d else { return }
            Task { await d.update(members) }
        }
    }

    /// The one button, by the rule of the shortcut: a computer's copy of a
    /// moment ago comes to the phone; otherwise a new text on the phone goes
    /// to the computers; otherwise the computers' latest text comes.
    func sync() async throws -> AppModel.SyncResult {
        guard let node, let g = state else { throw PendingGroup.Failure.noComputers }
        online = await node.connected
        let pb = UIPasteboard.general
        // A text first, as most copies with an image carry its text too;
        // an image compares by its hash.
        let text = pb.hasStrings ? pb.string : nil
        let image = text == nil ? Images.read(pb) : nil
        if text == nil, image == nil, pb.numberOfItems > 0 {
            throw ClipboardUnreadable(items: pb.numberOfItems, hasStrings: pb.hasStrings, types: pb.types, changeCount: pb.changeCount)
        }
        let board = image?.key ?? text
        let cur = await node.current
        let curImage = Images.part(of: cur?.media)
        let curFiles = cur?.media.flatMap { $0.isFiles ? $0 : nil }
        // An image compares by its hash, a text by itself; files count
        // until the button saved them once.
        var usable = await node.usable
        if let sum = curImage?.sha256 { usable = (Images.key(sum), .media) }
        if let cur, curFiles != nil { usable = cur.id == savedFiles ? nil : (text: "\u{0}files:" + cur.id, kind: Member.Kind.media) }
        func fetch() async throws -> AppModel.SyncResult {
            if let cur, let curFiles {
                guard await connected(node) else { throw PendingGroup.Failure.noComputers }
                try await save(cur, files: curFiles)
                savedFiles = cur.id
                return .savedFiles
            }
            if let cur, let curImage {
                try await receive(cur, image: curImage)
            } else if let u = usable {
                write(u.text, kind: u.kind)
            }
            let preview = curImage == nil && usable?.kind == .text ? usable.map { Self.preview($0.text) } : nil
            return .fetched(from: cur.flatMap { c in devices.first { $0.id == c.origin && !$0.isSelf }?.name }, preview: preview)
        }
        if let cur, let u = usable, cur.origin != g.device, cur.via == .copy, cur.ageMS < Self.recentCopyMS, u.text != board {
            return try await fetch()
        }
        if let t = board, !t.isEmpty, t != usable?.text {
            guard await connected(node) else { throw PendingGroup.Failure.noComputers }
            if let image {
                await node.send(text: "", kind: .text, media: Content.manifest(store: content, data: [(image.type, image.data)]))
            } else {
                await node.send(text: t, kind: .text)
            }
            return .sent(to: devices.filter { online.contains($0.id) && !$0.isSelf }.map(\.name).sorted())
        }
        if let u = usable, u.text != board {
            return try await fetch()
        }
        if !(await connected(node)) { throw PendingGroup.Failure.noComputers }
        return .nothingNew
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
    private func connected(_ node: MemberNode) async -> Bool {
        let deadline = ContinuousClock.now + Self.connectWait
        while true {
            online = await node.connected
            if !online.isEmpty || ContinuousClock.now >= deadline { return !online.isEmpty }
            try? await Task.sleep(for: .milliseconds(250))
        }
    }

    /// The files event the button saved last, so it does not save them again.
    private var savedFiles: String?

    /// Fetches the files a computer copied into the app's folder in Files,
    /// Received, with their folders; a name taken there gets a number.
    private func save(_ e: Member.Event, files m: Media.Manifest) async throws {
        guard let node else { throw PendingGroup.Failure.noComputers }
        if m.size > Images.maxCopy { throw Content.Failure.tooLarge(size: m.size, limit: Images.maxCopy) }
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
        for p in m.parts {
            guard let path = p.path else { continue }
            let url = target(path)
            if p.dir {
                try fm.createDirectory(at: url, withIntermediateDirectories: true)
                continue
            }
            try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let tmp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).part")
            fm.createFile(atPath: tmp.path, contents: nil)
            let h = try FileHandle(forWritingTo: tmp)
            do {
                if p.size > 0 {
                    try await Content.fetch(from: node, event: e, part: p, limit: Images.maxCopy,
                                            start: { try h.truncate(atOffset: 0) }, sink: { try h.write(contentsOf: $0) })
                }
                try h.close()
                try fm.moveItem(at: tmp, to: url)
            } catch {
                try? h.close()
                try? fm.removeItem(at: tmp)
                throw error
            }
        }
    }

    /// Fetches a computer's image whole and puts it on this phone's
    /// clipboard, with its text.
    private func receive(_ e: Member.Event, image part: Media.Part) async throws {
        guard let node else { throw PendingGroup.Failure.noComputers }
        let data = try await Content.data(from: node, event: e, part: part, limit: Images.maxCopy)
        Images.write(data, type: part.type ?? "image/png", alt: e.text)
    }

    /// Puts a text into the phone's clipboard; a secret stays on this phone
    /// only and for its remaining minute.
    private func write(_ text: String, kind: Member.Kind) {
        if kind == .secret {
            UIPasteboard.general.setItems([[UTType.plainText.identifier: text]],
                                          options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(SyncEngine.secretTTL)])
        } else {
            UIPasteboard.general.string = text
        }
    }
}
