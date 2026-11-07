// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import Foundation
import os
import SwiftUI
import UIKit

private let log = Logger(subsystem: "tools.cbb", category: "app")

/// The group as the app sees it: whether there is one, its computers,
/// admitting a device and joining another phone's group. LiveGroup is the
/// real one; PendingGroup stands in for previews.
@MainActor
protocol GroupController: AnyObject {
    var hasGroup: Bool { get }
    /// The group's tag, which the arrangement of the tiles is kept for;
    /// nil without a group.
    var groupTag: String? { get }
    /// Whether this phone may add and remove devices.
    var isAdmin: Bool { get }
    var computers: [AppModel.Computer] { get }
    /// Every device of the group, this phone included.
    var devices: [AppModel.Computer] { get }
    /// Makes this phone's own key, which proves it to the other devices,
    /// unless it has one.
    func prepare() throws
    /// Removes a device from the group.
    func remove(_ id: String) async throws
    /// Whether the group removed this phone.
    var removed: Bool { get }
    /// Takes this phone out of its group: deletes its keys and the
    /// group's files and keeps the settings.
    func leave() async throws
    /// Makes a computer an admin; only the root phone does.
    func makeAdmin(_ id: String) async throws
    /// When the group's recovery key was made; nil without one.
    var recoveryMade: Date? { get }
    /// Makes the group's recovery key, replacing the one before it, and
    /// returns its sheet, which the app shows once; only the root phone does.
    func makeRecovery() async throws -> Core.RecoverySheet
    /// Puts a new recovery key on a YubiKey held to the phone, checked
    /// with pin, replacing the one before it; returns its slot. Only the
    /// root phone does.
    func makeRecoveryOnCard(pin: String) async throws -> UInt8
    /// Removes the group's recovery key; only the root phone does.
    func removeRecovery() async throws
    /// The group's key level (Records.keyLevels) on the root phone; nil elsewhere.
    var keyLevel: String? { get }
    /// Sets the group's key level; only the root phone does.
    func setKeyLevel(_ level: String) async throws
    /// How long a copy from another device stays live after it arrives, in
    /// milliseconds.
    var incomingMS: Int64 { get }
    /// Sets it; the root and the admin phones do.
    func setIncoming(ms: Int64) async throws
    /// Unfreezes an admin computer that another admin froze.
    func unfreeze(_ id: String) async throws
    /// Whether this phone holds the group's root.
    var isRoot: Bool { get }
    /// What the group's records stop and what ends it (GroupAlert).
    var alerts: [GroupAlert] { get }
    /// Voids the records ids as the group's root, after Face ID: ends a
    /// conflict or cancels a claim.
    func resolve(_ ids: [Data]) async throws
    /// Whether the group's root handed the group to this phone (cbb
    /// handover), which has not taken it yet.
    var handedOver: Bool { get }
    /// Takes the group the root handed to this phone.
    func takeHandedGroup() async throws
    /// Makes the key the paired watch made an admin key with the role
    /// watch; only the root phone does. Returns what the watch keeps.
    func addWatch(_ request: WatchState.KeyRequest) async throws -> WatchState.Admission
    /// What the group's watch may do to a device (PhoneGroup.WatchAction).
    func watchActions(for id: String) -> [String]
    /// The body the watch signs for what it asked.
    func watchBody(_ ask: WatchState.Ask) throws -> Data
    /// Brings what the watch signed into the group: a record to every member,
    /// a command to its device.
    func deliverFromWatch(_ signed: WatchState.Signed) async throws
    /// Gives a device another name; only an admin phone does.
    func rename(_ id: String, to name: String) async throws
    /// Sets the sync mode of a connected computer; only an admin phone does.
    func setMode(_ id: String, to mode: String) async throws
    /// Keeps the group's copies out of this phone for forMS milliseconds, 0
    /// for until resumeReceiving; its own copies still go out.
    func pauseReceiving(forMS: Int64) throws
    /// Takes the group's copies again.
    func resumeReceiving() throws
    /// Mutes a device for the group for forMS milliseconds, 0 for until it
    /// is unmuted, or unmutes it; only an admin phone does.
    func setMuted(_ id: String, _ on: Bool, forMS: Int64) async throws
    /// Puts text where a computer's focus is; only an admin phone does.
    func paste(_ id: String, text: String, method: String, enter: Bool, secret: Bool) async throws
    /// Runs a quick action on a device; only an admin phone does.
    func runAction(_ id: String, name: String) async throws
    /// Turns every quick action off on a device; only an admin phone does.
    func actionsOff(_ id: String) async throws
    /// Admits the device whose QR code the user scanned; retrying is told
    /// each time the device did not answer yet and is dialed again.
    func admit(_ code: JoinCode, retrying: @escaping @MainActor () -> Void) async throws
    /// Joins another phone's group: listens, hands show the QR code for the
    /// other phone to scan, and returns once this phone is in the group.
    func join(show: @escaping @MainActor (JoinCode) -> Void) async throws
    /// Joins a computer's group with the code cbb pair shows on its root.
    func joinComputer(code: String) async throws
    /// Restores the group on this new phone with the recovery key from the
    /// sheet's QR code; returns once the claim is sent.
    func restore(sheet: Core.RecoveredKey) async throws
    /// The same with the recovery key on a YubiKey, held to the phone
    /// twice: for this phone's certificate, then for the claim.
    func restoreWithCard(pin: String) async throws
    /// Takes the copy from another device that waits for this phone, or
    /// sends what it holds: board, or the clipboard read when it sends.
    func sync(board: AppModel.Board?) async throws -> AppModel.SyncResult
    /// Takes the copy from another device that waits for this phone, when
    /// one does; nil when none does.
    func takePending() async -> AppModel.SyncResult?
    /// Updates which computers are online.
    func refresh() async
    /// Sync away from home: whether it is on, where it stands and its last
    /// failure; nil without a group.
    func awayStatus() async -> (on: Bool, status: AwayFromHome.Status, error: Error?, hub: String?, hubs: [String])?
    /// Turns sync away from home on or off.
    func setAwayFromHome(_ on: Bool) async throws
    /// The phone as the group's hub; nil on a phone that cannot be it.
    func hubStatus() async -> AppModel.Hub?
    /// Makes this phone the group's hub, or stops it being the hub.
    func setPhoneHub(_ on: Bool) async throws
    /// Sets the hub's forwarder; both empty for the project's.
    func setForwarder(address: String, pin: String) async throws
    /// Sets how the hub's tunnel hides.
    func setHubDisguise(_ d: HubOnPhone.Disguise) async throws
    /// Remembers the network the phone is on as a home network of the hub.
    func addHomeNetwork() async throws
    /// Tells the group whether the app is in front, where the hub works.
    func setForeground(_ on: Bool)
    /// Opens a remote invitation on this phone, the hub, for a device far
    /// away; ask asks the user about the device that uses it, ended gets
    /// its name or why it ended without one.
    func invite(lifetime: Int, ask: @escaping @MainActor (PairingMember.Request) async -> Bool,
                ended: @escaping @MainActor (Result<String, Error>) -> Void) async throws -> AppModel.Invitation
    func moveHub(to id: String) async throws
    /// Makes a connected admin computer a hub of the group as well.
    func makeHub(_ id: String, forwardOnly: Bool) async throws
    /// The phone at a blind relay; nil without a group.
    func relayStatus() async -> AppModel.BlindRelay?
    /// Meets the group at a blind relay; both empty leave it.
    func setRelay(address: String, pin: String) async throws
}

extension GroupController {
    /// A stand-in tag for the tests' and previews' groups.
    var groupTag: String? { hasGroup ? "group" : nil }
    func unfreeze(_ id: String) async throws {}
    var removed: Bool { false }
    func leave() async throws { throw LiveGroup.Failure.noGroup }
    var isRoot: Bool { false }
    var alerts: [GroupAlert] { [] }
    var recoveryMade: Date? { nil }
    func makeRecovery() async throws -> Core.RecoverySheet { throw PhoneGroup.Failure.notRoot }
    func makeRecoveryOnCard(pin: String) async throws -> UInt8 { throw PhoneGroup.Failure.notRoot }
    func removeRecovery() async throws { throw PhoneGroup.Failure.notRoot }
    var keyLevel: String? { nil }
    func setKeyLevel(_ level: String) async throws { throw PhoneGroup.Failure.notRoot }
    var incomingMS: Int64 { Records.defaultIncomingMS }
    func setIncoming(ms: Int64) async throws { throw PhoneGroup.Failure.notAdmin }
    func takePending() async -> AppModel.SyncResult? { nil }
    func resolve(_ ids: [Data]) async throws {}
    var handedOver: Bool { false }
    func takeHandedGroup() async throws {}
    func addWatch(_ request: WatchState.KeyRequest) async throws -> WatchState.Admission { throw PhoneGroup.Failure.notRoot }
    func watchActions(for id: String) -> [String] { [] }
    func watchBody(_ ask: WatchState.Ask) throws -> Data { throw PhoneGroup.Failure.notAWatch }
    func deliverFromWatch(_ signed: WatchState.Signed) async throws { throw PhoneGroup.Failure.notAWatch }
    func joinComputer(code: String) async throws { throw PendingGroup.Failure.notReady }
    func restore(sheet: Core.RecoveredKey) async throws { throw PendingGroup.Failure.notReady }
    func restoreWithCard(pin: String) async throws { throw PendingGroup.Failure.notReady }
    func rename(_ id: String, to name: String) async throws {}
    func setMode(_ id: String, to mode: String) async throws {}
    func pauseReceiving(forMS: Int64) throws {}
    func resumeReceiving() throws {}
    func setMuted(_ id: String, _ on: Bool, forMS: Int64) async throws {}
    func paste(_ id: String, text: String, method: String, enter: Bool, secret: Bool) async throws {}
    func runAction(_ id: String, name: String) async throws {}
    func actionsOff(_ id: String) async throws {}
    func awayStatus() async -> (on: Bool, status: AwayFromHome.Status, error: Error?, hub: String?, hubs: [String])? { nil }
    func setAwayFromHome(_ on: Bool) async throws {}
    func hubStatus() async -> AppModel.Hub? { nil }
    func setPhoneHub(_ on: Bool) async throws {}
    func setForwarder(address: String, pin: String) async throws {}
    func setHubDisguise(_ d: HubOnPhone.Disguise) async throws {}
    func addHomeNetwork() async throws {}
    func setForeground(_ on: Bool) {}
    func invite(lifetime: Int, ask: @escaping @MainActor (PairingMember.Request) async -> Bool,
                ended: @escaping @MainActor (Result<String, Error>) -> Void) async throws -> AppModel.Invitation {
        throw HubOnPhone.Failure.notRunning
    }
    func moveHub(to id: String) async throws { throw HubOnPhone.Failure.notRunning }
    func makeHub(_ id: String, forwardOnly: Bool) async throws { throw HubOnPhone.Failure.notRunning }
    func relayStatus() async -> AppModel.BlindRelay? { nil }
    func setRelay(address: String, pin: String) async throws {}
}

/// What the app shows and does; the views only read it and call it.
@MainActor
final class AppModel: ObservableObject {
    /// The one model of the running app, which the Shortcuts action uses
    /// too.
    static let shared = AppModel(group: LiveGroup(), notifies: true)

    enum Phase: Equatable { case start, joining, joiningComputer, home }

    /// A device of the group: a computer, or this phone.
    struct Computer: Identifiable, Equatable {
        let id: String
        var name: String
        /// Connected to this phone, or to a computer that is (throughHub).
        var online: Bool
        /// Online only through a connected computer, the hub away from
        /// home, which passes commands on to it (docs/protocol.md, section
        /// 4, "Reach"); a hub command still needs it connected here.
        var throughHub = false
        /// "full", "phone", "lite" or "watch".
        var role = "full"
        /// Its operating system; nil when its record does not tell.
        var os: String?
        var isSelf = false
        /// An admin phone: it may add and remove devices.
        var admin = false
        /// The phone that holds the group's root.
        var isRoot = false
        /// A computer this phone, the root, can make an admin: it offers an
        /// admin key.
        var canMakeAdmin = false
        /// Its keys sit in a file, as its hello or else its record says: a
        /// thief with it can copy them.
        var keysInFile = false
        /// It is a rootless install, as its hello or else its record says:
        /// never an admin or a hub (D-79).
        var rootless = false
        /// An admin computer another admin froze: the root or an admin phone
        /// unfreezes or removes it.
        var frozen = false
        /// What its hello says about its device, while it is connected.
        var device: Member.DeviceInfo?
        /// Its sync mode, as its hello says, while it is connected.
        var mode: String?
        /// The quick actions its hello says are on, while it is connected.
        var actions: [String] = []
        /// The records let it be a hub: the root's own device, an admin
        /// with the hub power, or a hub that only passes copies on.
        var mayHub = false
        /// A hub that only passes the copies on: none is sealed to it.
        var forwardOnly = false
        /// An admin muted it: its copies stay its own (design.md, "Muting a
        /// device"). This phone's own, or what a connected device's hello says.
        var muted: Hold?
        /// This phone takes no copies from the group for now; only on its
        /// own entry.
        var paused: Hold?
    }

    /// A mute or a pause that holds: until when, nil for until it is lifted.
    struct Hold: Equatable {
        var until: Date?

        /// From Unix milliseconds, 0 for until it is lifted; nil for none or
        /// one that ended.
        init?(ms: Int64?, now: Date = Date()) {
            guard let ms else { return nil }
            if ms == 0 { until = nil; return }
            let end = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
            guard end > now else { return nil }
            until = end
        }

        init(until: Date?) { self.until = until }
    }

    /// This phone's pause of the group's copies; nil while it takes them.
    var pause: Hold? { devices.first(where: \.isSelf)?.paused }

    /// What the phone's clipboard holds, as the paste button or Shortcuts
    /// hands it to the app: a text, or an image.
    struct Board {
        var text: String?
        var image: Images.Copied?
        /// What the button compares with the group's text: an image by its
        /// hash, which no text equals.
        var key: String? { image?.key ?? text }

        /// The board an item provider of the paste button holds: a text
        /// first, as most copies with an image carry its text too.
        static func load(_ providers: [NSItemProvider]) async -> Board {
            for p in providers where p.canLoadObject(ofClass: NSString.self) {
                let text: String? = await withCheckedContinuation { c in
                    _ = p.loadObject(ofClass: NSString.self) { s, _ in c.resume(returning: s as? String) }
                }
                if let text, !text.isEmpty { return Board(text: text) }
            }
            for p in providers {
                if let image = await Images.load(p) { return Board(image: image) }
            }
            return Board()
        }
    }

    enum SyncResult: Equatable {
        /// Sent to the computers connected, by name (none known: empty).
        case sent(to: [String])
        /// Fetched into the clipboard: from the computer that copied it, and
        /// the start of a text.
        case fetched(from: String?, preview: String?)
        case nothingNew
        /// Files a computer copied, saved in the app's folder in Files.
        case savedFiles
    }

    enum ScanResult: Equatable {
        case joinCode(JoinCode)
        case notCBB
    }

    @Published private(set) var phase: Phase
    @Published private(set) var computers: [Computer] = []
    @Published private(set) var devices: [Computer] = [] {
        didSet { loadArrangement() }
    }
    /// The user's order of the tiles and their collections (docs/apps.md,
    /// "Collections and the order of the tiles"), kept on this phone only;
    /// nil without a group.
    @Published private(set) var arrangement: Arrangement?
    /// One line about the last action, in plain words.
    @Published var message: String?
    @Published private(set) var busy = false
    /// How many times a device being added that has not answered yet was
    /// dialed again; 0 before that.
    @Published private(set) var retries = 0
    /// The QR code this phone shows while it waits to join a group.
    @Published private(set) var joinCode: JoinCode?
    @Published private(set) var isAdmin = true
    /// Whether this phone holds the group's root, which ends conflicts.
    @Published private(set) var isRoot = false
    /// When the group's recovery key was made; nil without one.
    @Published private(set) var recoveryMade: Date?
    /// The group's key level on the root phone; nil elsewhere.
    @Published private(set) var keyLevel: String?
    /// What the group's records stop and what ends it.
    @Published private(set) var alerts: [GroupAlert] = []
    /// Whether the group's root handed the group to this phone, which may
    /// take it now.
    @Published private(set) var handedOver = false
    /// The group removed this phone; the app offers to leave.
    @Published private(set) var removed = false
    /// The one-time note on the Start screen that this phone is ready.
    @Published private(set) var welcome = false

    /// Sync away from home as Settings shows it: nil without a group.
    struct Away: Equatable {
        var on: Bool
        var status: AwayFromHome.Status
        /// The last failure while it is still trying, in words.
        var error: String?
        /// The hub the phone reaches now, by device ID; nil while it reaches none.
        var hub: String?
        /// The group's hubs whose offers the phone keeps, highest first.
        var hubs: [String] = []
    }

    /// Where a device stands among the group's hubs, as the device list and
    /// its page show it.
    enum HubMark: Equatable {
        /// One of the group's hubs.
        case hub
        /// The hub this phone reaches now.
        case inUse
    }

    /// Whether d is one of the group's hubs, as this phone knows: this phone
    /// while it is the hub, or a hub whose offer it keeps; nil otherwise.
    func hubMark(_ d: Computer) -> HubMark? {
        if d.isSelf { return hub?.on == true ? .hub : nil }
        guard let a = away, a.on else { return nil }
        if a.hub == d.id, a.status == .connected || a.status == .atHome { return .inUse }
        return a.hubs.contains(d.id) ? .hub : nil
    }

    @Published private(set) var away: Away?
    /// What turning it on or off said, when it failed.
    @Published private(set) var awayNote: String?

    /// The phone as the group's hub as Settings and Home show it: nil on a
    /// phone that cannot be the hub. home tells whether the phone is on
    /// one of the hub's home networks now.
    struct Hub: Equatable {
        var on: Bool
        var status: HubOnPhone.Status
        /// Why the forwarder does not take it, as cbbtun says.
        var error: String?
        var forwarder: HubState.Forwarder?
        /// The project's forwarder does not take it and the phone holds no
        /// signed entry points that have not expired (docs/protocol.md,
        /// section 16): a new list may be what it needs.
        var entriesStale = false
        var home = false
        var clients = 0
        /// How its tunnel hides.
        var disguise = HubOnPhone.Disguise.plain
        /// The connected computers the hub can move to: admins, or
        /// computers the root can make admins.
        var computers: [Target] = []
        /// The computer that is always on which the app suggests as the
        /// hub, unless the user chose to keep the phone.
        var suggested: Target?

        struct Target: Equatable, Identifiable {
            let id: String
            let name: String
        }
    }

    @Published private(set) var hub: Hub?

    /// The phone at a blind relay as Settings shows it (docs/design.md,
    /// "Blind relay"): where it stands, why the relay does not take it, the
    /// relay, and the group's devices there and the connections through it.
    struct BlindRelay: Equatable {
        var status: RelayOnPhone.Status
        var error: String?
        var relay: HubState.Forwarder?
        var online = 0
        var through = 0
    }

    @Published private(set) var blindRelay: BlindRelay?
    /// What the last change to the relay said, when it failed.
    @Published private(set) var relayNote: String?
    /// The relay's last error, logged once.
    private var relayError: String?
    /// What the last change to the hub said, when it failed.
    @Published private(set) var hubNote: String?

    /// An open remote invitation: its text, when it expires, and how to
    /// cancel it.
    struct Invitation {
        var text: String
        var expires: Date
        var cancel: () -> Void
    }

    /// A remote invitation as Settings shows it: when it expires, the file
    /// to share, and the device waiting for the user's answer.
    struct Invite {
        var expires: Date
        var file: URL
        var request: PairingMember.Request?
    }

    @Published private(set) var invite: Invite?
    /// How the last invitation ended, or why it did not open.
    @Published private(set) var inviteNote: String?
    private var invitation: Invitation?
    private var answer: CheckedContinuation<Bool, Never>?
    /// How long an invitation from the phone is valid: an hour, as cbb
    /// invite's default.
    static let inviteLifetime = 3600
    /// The registration's last error, logged once.
    private var hubError: String?

    let group: GroupController
    private let defaults: UserDefaults
    /// The running app's model notifies of the group's events and tells the
    /// watch; the tests' and previews' do neither.
    private let notifies: Bool
    static let welcomedKey = "welcomed"

    /// nil means PendingGroup, made here because a default argument is
    /// evaluated outside the main actor.
    init(group: GroupController? = nil, defaults: UserDefaults = .standard, notifies: Bool = false) {
        let group = group ?? PendingGroup()
        self.group = group
        self.defaults = defaults
        self.notifies = notifies
        phase = group.hasGroup ? .home : .start
        computers = group.computers
        devices = group.devices
        isAdmin = group.isAdmin
        loadArrangement()
    }

    /// Reads what the camera saw, or what the user typed: the text of the QR
    /// code of cbb pair.
    nonisolated static func read(scanned text: String) -> ScanResult {
        guard let jc = JoinCode(qr: text), jc.codeIsValid, !jc.addrs.isEmpty, !jc.fingerprint.isEmpty else { return .notCBB }
        return .joinCode(jc)
    }

    /// Admits a scanned computer; on success the app goes Home.
    func scanned(_ text: String) async -> Bool {
        guard case let .joinCode(jc) = Self.read(scanned: text) else {
            message = String(localized: "Not a CBB QR code.", bundle: .app)
            return false
        }
        busy = true
        retries = 0
        defer {
            busy = false
            retries = 0
        }
        Island.show(.adding, String(localized: "Adding a device…", bundle: .app))
        do {
            try await group.admit(jc) { [weak self] in self?.retries += 1 }
            computers = group.computers
            devices = group.devices
            phase = .home
            message = nil
            Island.end(.adding, last: String(localized: "The device is in the group.", bundle: .app))
            return true
        } catch is CancellationError {
            Island.end(.adding)
            return false
        } catch {
            message = Self.describe(error)
            Island.end(.adding, last: String(localized: "The device was not added.", bundle: .app))
            return false
        }
    }

    /// At the first launch: makes this phone's own key and says so once,
    /// with what to do next.
    func prepare() {
        guard phase == .start, !defaults.bool(forKey: Self.welcomedKey) else { return }
        do {
            try group.prepare()
            welcome = true
        } catch {
            message = Self.describe(error)
        }
    }

    /// Hides the note for good.
    func dismissWelcome() {
        welcome = false
        defaults.set(true, forKey: Self.welcomedKey)
    }

    /// Opens the screen that joins another phone's group.
    func startJoining() {
        dismissWelcome()
        message = nil
        phase = .joining
    }

    /// Joins another phone's group: shows this phone's QR code until an
    /// admin phone scans it, then goes Home. The join screen runs it as its
    /// task, so leaving the screen cancels it and stops listening.
    func join() async {
        do {
            try await group.join { [weak self] code in self?.joinCode = code }
            computers = group.computers
            devices = group.devices
            isAdmin = group.isAdmin
            phase = .home
        } catch is CancellationError {
        } catch {
            message = Self.describe(error)
        }
        joinCode = nil
    }

    /// Opens the screen that joins a computer's group with the code cbb
    /// pair shows.
    func startJoiningComputer() {
        dismissWelcome()
        message = nil
        phase = .joiningComputer
    }

    /// Joins a computer's group with the code the user typed from cbb pair
    /// on the group's root, then goes Home. A wrong code may be typed again:
    /// the computer's window takes three attempts.
    func joinComputer(code: String) async {
        busy = true
        message = nil
        defer { busy = false }
        do {
            try await group.joinComputer(code: code)
            computers = group.computers
            devices = group.devices
            isAdmin = group.isAdmin
            phase = .home
        } catch is CancellationError {
        } catch {
            message = Self.describe(error, summary: Self.joinSummary(error))
        }
    }

    /// What joining a computer's group says about a failure of the
    /// exchange; nil for the others, which say what they always do.
    private static func joinSummary(_ error: Error) -> String? {
        let f = (error as? PairingJoiner.Spent)?.underlying as? PairingJoiner.Failure ?? error as? PairingJoiner.Failure
        if case .refused(.wrongCode)? = f {
            return String(localized: "The code did not match. Check the code on the computer's screen and type it again.", bundle: .app)
        }
        if f != nil || error is PairingJoiner.Spent {
            return String(localized: "The computer's group could not be joined. Run cbb pair -admin on it again.", bundle: .app)
        }
        return nil
    }

    /// Restores the group with the recovery key from the sheet's QR code,
    /// on a phone without a group: the claim goes out, the app goes Home,
    /// and Home shows the time left until this phone becomes the root.
    func restore(_ text: String) async -> Bool {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard phase == .start else {
            message = String(localized: "This phone is in a group already. A recovery sheet restores a group on a phone without one.", bundle: .app)
            return false
        }
        busy = true
        defer { busy = false }
        do {
            switch try Core.readRecoverySheet(text) {
            case let .refused(_, why):
                let summary = String(localized: "This is not the QR code of a recovery sheet.", bundle: .app)
                message = Self.showsErrorDetails ? summary + "\n\n" + why : summary
                return false
            case let .key(sheet):
                try await group.restore(sheet: sheet)
            }
            computers = group.computers
            devices = group.devices
            isAdmin = group.isAdmin
            phase = .home
            message = String(localized: "The claim is sent. This phone becomes the group's root when the waiting time ends; Home shows the time left.", bundle: .app)
            return true
        } catch is CancellationError {
            return false
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// Restores the group with the recovery key on a YubiKey, as restore
    /// does with the sheet.
    func restoreWithCard(pin: String) async -> Bool {
        guard phase == .start else {
            message = String(localized: "This phone is in a group already. A recovery key restores a group on a phone without one.", bundle: .app)
            return false
        }
        busy = true
        defer { busy = false }
        do {
            try await group.restoreWithCard(pin: pin)
            computers = group.computers
            devices = group.devices
            isAdmin = group.isAdmin
            phase = .home
            message = String(localized: "The claim is sent. This phone becomes the group's root when the waiting time ends; Home shows the time left.", bundle: .app)
            return true
        } catch is CancellationError {
            return false
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// Leaves the join screen without joining.
    func cancelJoin() {
        joinCode = nil
        message = nil
        phase = .start
    }

    /// The one big button: the paste button hands over board; a button
    /// that is not one lets the app read the clipboard when it sends.
    func sync(board: Board? = nil) async {
        busy = true
        defer { busy = false }
        do {
            let result = try await group.sync(board: board)
            message = Self.said(result)
            if let message { Island.flash(message) }
            feel(result == .nothingNew ? .warning : .success)
        } catch {
            message = Self.describe(error)
            feel(.error)
        }
        computers = group.computers
    }

    /// What the button says it did: where a text went or came from, and
    /// that it is ready to paste.
    nonisolated static func said(_ result: SyncResult) -> String {
        switch result {
        case .sent(let to) where !to.isEmpty:
            let names = to.formatted(.list(type: .and))
            return String(localized: "Sent to \(names).", bundle: .app)
        case .sent:
            return String(localized: "Sent to the computers.", bundle: .app)
        case .fetched(let from?, let preview?):
            return String(localized: "Ready to paste: “\(preview)” from \(from).", bundle: .app)
        case .fetched(let from?, nil):
            return String(localized: "Ready to paste, from \(from).", bundle: .app)
        case .fetched:
            return String(localized: "Ready to paste.", bundle: .app)
        case .nothingNew:
            return String(localized: "Nothing new to send or fetch.", bundle: .app)
        case .savedFiles:
            return String(localized: "Saved in Files, On My iPhone, CBB.", bundle: .app)
        }
    }

    /// A tap in the hand when the button is done, while the app is in front:
    /// iOS plays none for an app in the background, as for Back Tap.
    private func feel(_ kind: UINotificationFeedbackGenerator.FeedbackType) {
        guard UIApplication.shared.applicationState == .active else { return }
        UINotificationFeedbackGenerator().notificationOccurred(kind)
    }

    /// Takes the copy from another device that waits for this phone, as
    /// the app comes to the front, and says so.
    func takePending() async {
        guard let result = await group.takePending() else { return }
        message = Self.said(result)
        if let message { Island.flash(message) }
        computers = group.computers
    }

    /// The sync the Shortcuts action runs, with the app perhaps just
    /// started for it: the Home button's, after waiting up to wait for a
    /// computer to connect, with text from Shortcuts' Get Clipboard, which
    /// an app in the background cannot read itself. Returns what it says.
    func syncFromShortcut(text: String? = nil, wait: Duration = .seconds(5), progress: Progress? = nil) async -> String {
        let deadline = ContinuousClock.now + wait
        if group.hasGroup, !computers.contains(where: \.online) {
            let line = String(localized: "Connecting to the computers…", bundle: .app)
            progress?.localizedDescription = line
            Island.show(.exchange, line)
        }
        defer { progress?.completedUnitCount = progress?.totalUnitCount ?? 0 }
        while group.hasGroup, ContinuousClock.now < deadline {
            await refresh()
            if computers.contains(where: \.online) { break }
            try? await Task.sleep(for: .milliseconds(250))
        }
        progress?.completedUnitCount = 1
        progress?.localizedDescription = String(localized: "Syncing…", bundle: .app)
        await sync(board: text.map { Board(text: $0) })
        return message ?? ""
    }

    /// Hears of the group's events while iOS runs the app in the
    /// background for a moment (BackgroundRefresh): it waits up to wait for
    /// a computer to connect, then gives the records a moment to arrive.
    /// The clipboard stays as it is: iOS lets only the app in front read it.
    func refreshInBackground(wait: Duration = .seconds(20), records: Duration = .seconds(3)) async {
        let deadline = ContinuousClock.now + wait
        while group.hasGroup, ContinuousClock.now < deadline {
            await refresh()
            if computers.contains(where: \.online) {
                try? await Task.sleep(for: records)
                await refresh()
                return
            }
            try? await Task.sleep(for: .milliseconds(500))
        }
    }

    /// Updates which computers are online.
    func refresh() async {
        await group.refresh()
        computers = group.computers
        devices = group.devices
        isRoot = group.isRoot
        alerts = group.alerts
        handedOver = group.handedOver
        removed = group.removed
        recoveryMade = group.recoveryMade
        keyLevel = group.keyLevel
        incomingMS = group.incomingMS
        await refreshAway()
        await refreshHub()
        await refreshRelay()
        if notifies {
            Notifier.shared.observe(devices)
            WatchLink.shared.update(self)
        }
    }

    private func refreshAway() async {
        guard let a = await group.awayStatus() else {
            away = nil
            Island.end(.away)
            return
        }
        // Through the tunnel, the island says so for as long as it lasts.
        if a.on, a.status == .connected {
            Island.show(.away, String(localized: "Away from home: through your hub", bundle: .app))
        } else {
            Island.end(.away)
        }
        // The last failure only while it is still trying; once connected or
        // at home it is old news. AwayFromHome logs each failure itself.
        let failing = a.status == .connecting ? a.error : nil
        if notifies { Notifier.shared.away(trying: a.on && failing != nil) }
        away = Away(on: a.on, status: a.status, error: failing.map {
            Self.describe($0, summary: String(localized: "The hub does not answer through the tunnel.", bundle: .app), log: false)
        }, hub: a.hub, hubs: a.hubs)
    }

    private func refreshHub() async {
        let h = await group.hubStatus()
        if h?.error != hubError {
            hubError = h?.error
            if let e = hubError { log.error("the hub: \(e, privacy: .public)") }
        }
        hub = h
    }

    private func refreshRelay() async {
        let r = await group.relayStatus()
        if r?.error != relayError {
            relayError = r?.error
            if let e = relayError { log.error("the relay: \(e, privacy: .public)") }
        }
        blindRelay = r
    }

    /// Meets the group at the blind relay at address with the key pin, as
    /// cbb relay prints them, after the user read what it learns; both
    /// empty leave it.
    func setRelay(address: String, pin: String) async {
        do {
            try await group.setRelay(address: address, pin: pin)
            relayNote = nil
        } catch RelayOnPhone.Failure.badRelay {
            relayNote = Self.describe(RelayOnPhone.Failure.badRelay, summary: String(
                localized: "Give the relay's address with its port and its key, as cbb relay prints them, or leave both empty.",
                bundle: .app))
        } catch {
            relayNote = Self.describe(error)
        }
        await refreshRelay()
    }

    /// Makes this phone the group's hub, or stops it being the hub.
    func setHub(_ on: Bool) async { await hubChange { try await self.group.setPhoneHub(on) } }

    /// Makes a connected computer the hub in place of this phone
    /// (docs/protocol.md, section 11, "Moving the hub").
    func moveHub(to id: String) async {
        do {
            try await group.moveHub(to: id)
            hubNote = String(localized: "The computer is the hub now; this phone reaches it from afar.", bundle: .app)
        } catch HubOnPhone.Failure.notRunning {
            hubNote = Self.describe(HubOnPhone.Failure.notRunning,
                                    summary: String(localized: "The hub can move only while it runs with a forwarder.", bundle: .app))
        } catch {
            hubNote = Self.describe(error)
        }
        await refreshHub()
    }

    /// Makes a connected computer a hub of the group as well
    /// (docs/protocol.md, section 11, "Several hubs"): one that reads the
    /// copies, an admin, or one that only passes them on.
    func makeHub(_ id: String, forwardOnly: Bool = false) async {
        do {
            try await group.makeHub(id, forwardOnly: forwardOnly)
            message = forwardOnly
                ? String(localized: "It is a hub now that only passes the copies on: your devices reach the group through it when they are away from home, and it reads none of them.", bundle: .app)
                : String(localized: "It is a hub now: your devices reach the group through it when they are away from home.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        devices = group.devices
        await refreshHub()
    }

    /// Sets how the hub's tunnel hides: plain WireGuard, AmneziaWG or VLESS.
    func setHubDisguise(_ d: HubOnPhone.Disguise) async { await hubChange { try await self.group.setHubDisguise(d) } }

    /// Keeps this phone as the hub: the app no longer suggests a computer.
    func keepPhoneHub() async {
        UserDefaults.standard.set(true, forKey: LiveGroup.keepsPhoneHubKey)
        await refreshHub()
    }

    /// Sets the hub's forwarder; both empty for the project's.
    func setForwarder(address: String, pin: String) async {
        await hubChange {
            let a = address.trimmingCharacters(in: .whitespaces), p = pin.trimmingCharacters(in: .whitespaces)
            guard a.isEmpty == p.isEmpty, p.isEmpty || HubState.validPin(p) else { throw HubOnPhone.Failure.badForwarder }
            try await self.group.setForwarder(address: a, pin: p)
        }
    }

    /// Remembers the network the phone is on as home.
    func addHomeNetwork() async { await hubChange { try await self.group.addHomeNetwork() } }

    private func hubChange(_ f: () async throws -> Void) async {
        do {
            try await f()
            hubNote = nil
        } catch HubOnPhone.Failure.badForwarder {
            hubNote = Self.describe(HubOnPhone.Failure.badForwarder, summary: String(
                localized: "Give the forwarder's address with its port and its key, as cbb forward prints them, or leave both empty.",
                bundle: .app))
        } catch {
            hubNote = Self.describe(error)
        }
        await refreshHub()
    }

    /// Opens a remote invitation for a device far away (docs/protocol.md,
    /// section 12), valid for an hour: Settings shares its file, and asks
    /// the user about the device that uses it.
    func openInvite() async {
        guard invite == nil else { return }
        do {
            let inv = try await group.invite(lifetime: Self.inviteLifetime, ask: { [weak self] req in
                await self?.ask(req) ?? false
            }, ended: { [weak self] r in self?.inviteEnded(r) })
            let file = try Self.inviteFile(inv.text)
            (invitation, invite, inviteNote) = (inv, Invite(expires: inv.expires, file: file), nil)
        } catch HubOnPhone.Failure.notRunning {
            inviteNote = Self.describe(HubOnPhone.Failure.notRunning, summary: String(
                localized: "An invitation needs the hub registered with its forwarder. Check the forwarder above.", bundle: .app))
        } catch {
            inviteNote = Self.describe(error)
        }
    }

    /// The invitation as a file of one line, cbb.cbbinvite, as
    /// cbb pair -invite reads it; it goes when the invitation ends.
    private static func inviteFile(_ text: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("invites", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("cbb.cbbinvite")
        try Data((text + "\n").utf8).write(to: url, options: [.atomic, .completeFileProtection])
        return url
    }

    /// Asks the user about a device that used the invitation, for up to 5
    /// minutes (docs/protocol.md, section 12).
    private func ask(_ req: PairingMember.Request) async -> Bool {
        answer?.resume(returning: false)
        invite?.request = req
        let timeout = Task { [weak self] in
            try? await Task.sleep(for: .seconds(300))
            if !Task.isCancelled { self?.answer(false) }
        }
        defer { timeout.cancel() }
        let yes = await withCheckedContinuation { answer = $0 }
        invite?.request = nil
        return yes
    }

    /// The user's answer about the device that used the invitation.
    func answer(_ yes: Bool) {
        answer?.resume(returning: yes)
        answer = nil
    }

    /// Cancels the open invitation.
    func cancelInvite() { invitation?.cancel() }

    private func inviteEnded(_ r: Result<String, Error>) {
        if let f = invite?.file { try? FileManager.default.removeItem(at: f) }
        answer(false)
        (invite, invitation) = (nil, nil)
        switch r {
        case .success:
            inviteNote = String(localized: "The device joined the group; it appears in the list once it connects.", bundle: .app)
            Task { await refresh() }
        case .failure(InvitationWindow.Ended.cancelled):
            inviteNote = nil
        case .failure(InvitationWindow.Ended.expired):
            inviteNote = String(localized: "The invitation expired without being used.", bundle: .app)
        case .failure(InvitationWindow.Ended.tooManyAttempts):
            inviteNote = String(localized: "The invitation closed after three failed attempts. Make a new one.", bundle: .app)
        case .failure(let e):
            inviteNote = Self.describe(e)
        }
    }

    /// Turns sync away from home on or off; the hub's answer comes on the
    /// next connection at home.
    func setAway(_ on: Bool) async {
        do {
            try await group.setAwayFromHome(on)
            awayNote = nil
        } catch {
            awayNote = Self.describe(error)
        }
        await refreshAway()
    }

    /// Removes a device from the group.
    func remove(_ id: String) async {
        do {
            try await group.remove(id)
            message = String(localized: "Removed. The other devices refuse it from now on.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        computers = group.computers
        devices = group.devices
        isAdmin = group.isAdmin
    }

    /// Takes this phone out of its group (D-83) and goes back to the Start
    /// screen, with a new key of its own for the next group. True when it
    /// left.
    func leave() async -> Bool {
        busy = true
        defer { busy = false }
        do {
            try await group.leave()
        } catch {
            message = Self.describe(error)
            return false
        }
        if notifies { Notifier.shared.forget() }
        do {
            try group.prepare()
        } catch {
            log.error("no new key after leaving: \(String(reflecting: error), privacy: .public)")
        }
        phase = .start
        message = nil
        await refresh()
        isAdmin = group.isAdmin
        removed = false
        if notifies { WatchLink.shared.update(self) }
        return true
    }

    /// Gives a device another name.
    func rename(_ id: String, to name: String) async {
        do {
            try await group.rename(id, to: name)
            message = String(localized: "Renamed. The other devices show the new name as soon as they hear of it.", bundle: .app)
        } catch PhoneGroup.Failure.invalidName {
            message = String(localized: "A name has 1 to 64 characters.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        computers = group.computers
        devices = group.devices
    }

    /// Ends a conflict or cancels a claim as the group's root: voids the
    /// alert's records.
    func resolve(_ alert: GroupAlert) async {
        do {
            try await group.resolve(alert.records)
            switch alert.kind {
            case .claimPending, .claimStopped, .claims:
                message = String(localized: "The claim is cancelled. The other devices hear of it as soon as they connect.", bundle: .app)
            default:
                message = String(localized: "Both histories are void. The device signs its records again by itself.", bundle: .app)
            }
        } catch {
            message = Self.describe(error)
        }
        devices = group.devices
        alerts = group.alerts
    }

    /// Takes the group the root handed to this phone (cbb handover), after
    /// Face ID.
    func takeHandedGroup() async {
        do {
            try await group.takeHandedGroup()
            message = String(localized: "This phone is the group's root now. The other devices hear of it as soon as they connect.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        await refresh()
    }

    /// Unfreezes an admin computer that another admin froze.
    func unfreeze(_ id: String) async {
        do {
            try await group.unfreeze(id)
            message = String(localized: "It is an admin again.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        devices = group.devices
    }

    /// Sets the sync mode of a connected computer.
    func setMode(_ id: String, to mode: String) async {
        do {
            try await group.setMode(id, to: mode)
            message = String(localized: "The sync mode is set.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        await group.refresh()
        devices = group.devices
    }

    /// Keeps the group's copies out of this phone for forMS milliseconds,
    /// 0 for until the user takes them again; nil takes them again now.
    func pauseReceiving(forMS: Int64?) {
        do {
            if let forMS { try group.pauseReceiving(forMS: forMS) } else { try group.resumeReceiving() }
            message = forMS == nil
                ? String(localized: "This phone takes copies from the group again.", bundle: .app)
                : String(localized: "This phone takes no copies from the group for now.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        devices = group.devices
    }

    /// Mutes a device for the whole group, or unmutes it.
    func setMuted(_ id: String, _ on: Bool, forMS: Int64 = 0) async {
        do {
            try await group.setMuted(id, on, forMS: forMS)
            message = on ? String(localized: "The device is muted: its copies stay its own.", bundle: .app)
                : String(localized: "The device is unmuted.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        await group.refresh()
        devices = group.devices
    }

    /// Puts text where a computer's focus is; true when it did.
    @discardableResult
    func paste(_ id: String, text: String, method: String, enter: Bool, secret: Bool) async -> Bool {
        do {
            try await group.paste(id, text: text, method: method, enter: enter, secret: secret)
            message = String(localized: "Pasted.", bundle: .app)
            return true
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// Runs a quick action on a device; true when it did.
    @discardableResult
    func runAction(_ id: String, name: String) async -> Bool {
        do {
            try await group.runAction(id, name: name)
            message = String(localized: "Done.", bundle: .app)
            return true
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// Turns every quick action off on a device.
    func actionsOff(_ id: String) async {
        do {
            try await group.actionsOff(id)
            message = String(localized: "The quick actions are off there.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        await group.refresh()
        devices = group.devices
    }

    /// Makes the paired Apple Watch an admin with a key of its own, for the
    /// emergency actions (docs/protocol.md, section 10, "Watches"): the watch,
    /// whose app is open, makes the key, and the root signs after Face ID.
    func addWatch() async {
        do {
            let request = try await WatchLink.shared.keyRequest()
            let admission = try await group.addWatch(request)
            try await WatchLink.shared.admit(admission)
            message = String(localized: "The watch is an admin now. It can freeze an admin computer, remove a device that is no admin and turn things off.", bundle: .app)
        } catch WatchLink.Failure.notReachable {
            message = String(localized: "Open CBB on the watch, then try again.", bundle: .app)
        } catch WatchLink.Failure.notProtected {
            message = String(localized: "The watch needs a passcode and wrist detection, and must be on your wrist. Turn them on in the Watch app on this iPhone.", bundle: .app)
        } catch WatchLink.Failure.noSecureEnclave {
            message = Self.describe(WatchLink.Failure.noSecureEnclave, summary: String(localized: "This watch cannot keep a key in its Secure Enclave.", bundle: .app))
        } catch {
            message = Self.describe(error)
        }
        devices = group.devices
    }

    /// Makes the group's recovery key and returns its sheet to show once;
    /// nil, with the message set, when it failed.
    func makeRecovery() async -> Core.RecoverySheet? {
        defer { recoveryMade = group.recoveryMade }
        do {
            return try await group.makeRecovery()
        } catch {
            message = Self.describe(error)
            return nil
        }
    }

    /// Puts a new recovery key on a YubiKey; true once it is there.
    func makeRecoveryOnCard(pin: String) async -> Bool {
        defer { recoveryMade = group.recoveryMade }
        do {
            _ = try await group.makeRecoveryOnCard(pin: pin)
            message = String(localized: "The recovery key is on the YubiKey. Keep it away from your phones; a sheet printed before no longer works.", bundle: .app)
            return true
        } catch is CancellationError {
            return false
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// Removes the group's recovery key.
    func removeRecovery() async {
        do {
            try await group.removeRecovery()
            message = String(localized: "The recovery key is removed. A sheet printed for it no longer works.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        recoveryMade = group.recoveryMade
    }

    /// How long a copy from another device stays live after it arrives, in
    /// milliseconds.
    @Published private(set) var incomingMS = Records.defaultIncomingMS

    /// Sets how long a copy from another device stays live after it arrives.
    func setIncoming(ms: Int64) async {
        do {
            try await group.setIncoming(ms: ms)
            message = String(localized: "Saved. Every device of the group follows it.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        incomingMS = group.incomingMS
    }

    /// Sets which keys may be the group's admins and hubs.
    func setKeyLevel(_ level: String) async {
        do {
            try await group.setKeyLevel(level)
            message = String(localized: "Saved. Every device of the group follows it.", bundle: .app)
        } catch PhoneGroup.Failure.belowKeyLevel {
            message = String(localized: "This phone's own key is not proven, so the group cannot ask for proven keys yet.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        keyLevel = group.keyLevel
    }

    /// Makes a computer an admin.
    func makeAdmin(_ id: String) async {
        do {
            try await group.makeAdmin(id)
            message = String(localized: "It is an admin now: it adds and removes devices with cbb pair and cbb remove.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        devices = group.devices
        keyLevel = group.keyLevel
    }

    /// A tile below this phone's: a device, or a collection with its
    /// devices as the group lists them.
    enum Arranged: Identifiable, Equatable {
        case device(Computer)
        case collection(Arrangement.Collection, [Computer])

        var id: String {
            switch self {
            case .device(let d): "d:" + d.id
            case .collection(let c, _): "c:" + c.id
            }
        }

        var ref: Arrangement.Ref {
            switch self {
            case .device(let d): .device(d.id)
            case .collection(let c, _): .collection(c.id)
            }
        }
    }

    static let arrangementKey = "deviceArrangement"

    /// This phone's own ID: first in the arrangement until the user moves it.
    private var selfID: String? { devices.first(where: \.isSelf)?.id }

    /// The devices and collections, this phone among them, in the user's
    /// order: the group's order, this phone first, until the user changes it.
    var arranged: [Arranged] {
        guard let a = arrangement else {
            return (devices.filter(\.isSelf) + devices.filter { !$0.isSelf }).map { .device($0) }
        }
        let byID = Dictionary(devices.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        return a.view(devices: devices.map(\.id), self: selfID).compactMap { item in
            switch item {
            case .device(let id): byID[id].map { .device($0) }
            case .collection(let c): .collection(c, c.devices.compactMap { byID[$0] })
            }
        }
    }

    /// The collection with the ID, as Home shows it.
    func collection(_ id: String) -> (Arrangement.Collection, [Computer])? {
        for case let .collection(c, ds) in arranged where c.id == id { return (c, ds) }
        return nil
    }

    /// The collections that a device can go into: every one but its own.
    func collections(apartFrom device: String) -> [Arrangement.Collection] {
        arranged.compactMap {
            guard case let .collection(c, _) = $0, !c.devices.contains(device) else { return nil }
            return c
        }
    }

    /// The collection a device is in, if any.
    func collection(holding device: String) -> Arrangement.Collection? {
        for case let .collection(c, _) in arranged where c.devices.contains(device) { return c }
        return nil
    }

    /// Reads the group's arrangement once its tag is known, and drops the
    /// devices that left once the list is whole: the group loaded, this
    /// phone in it. Until the user changes something nothing is stored.
    private func loadArrangement() {
        guard let tag = group.groupTag else {
            if arrangement != nil { arrangement = nil }
            return
        }
        var a = Arrangement.decode(defaults.data(forKey: Self.arrangementKey), group: tag)
        if let current = arrangement, current.group == tag { a = current }
        if selfID != nil, defaults.data(forKey: Self.arrangementKey) != nil {
            let before = a
            a.prune(devices: devices.map(\.id))
            if a != before { defaults.set(a.encoded(), forKey: Self.arrangementKey) }
        }
        if a != arrangement { arrangement = a }
    }

    /// Makes a change to the arrangement and keeps it; one that does not
    /// fit leaves it as it was and says so.
    @discardableResult
    func arrange(_ op: Arrangement.Op) -> Bool {
        guard var a = arrangement else { return false }
        do {
            try a.apply(op, devices: devices.map(\.id), self: selfID)
        } catch {
            message = Self.describe(error)
            return false
        }
        defaults.set(a.encoded(), forKey: Self.arrangementKey)
        arrangement = a
        return true
    }

    /// Makes a collection of the devices and returns its ID; nil when it
    /// does not fit (a name too long, too many collections).
    func newCollection(_ name: String, devices ids: [String]) -> String? {
        let before = Set(collectionIDs)
        guard arrange(.new(name: name, devices: ids)) else { return nil }
        return collectionIDs.first { !before.contains($0) }
    }

    private var collectionIDs: [String] {
        (arrangement?.items ?? []).compactMap { item -> String? in
            guard case let .collection(c) = item else { return nil }
            return c.id
        }
    }

    /// Whether a message names the error underneath, to find out what
    /// failed: on in debug builds, off in release ones, and either way the
    /// ShowErrorDetails default when it is set (in Xcode, the launch
    /// argument -ShowErrorDetails YES or NO).
    nonisolated static var showsErrorDetails: Bool {
        // bool(forKey:) reads YES and NO given as text too, as the launch
        // argument gives them.
        if UserDefaults.standard.object(forKey: "ShowErrorDetails") != nil { return UserDefaults.standard.bool(forKey: "ShowErrorDetails") }
        #if DEBUG
        return true
        #else
        return false
        #endif
    }

    /// The message for an error, with the error itself below it when
    /// details is set. The error is logged either way.
    static func describe(_ error: Error, details: Bool = showsErrorDetails, summary given: String? = nil, log logs: Bool = true) -> String {
        let text = given ?? summary(error), detail = String(reflecting: error)
        if logs { log.error("\(text, privacy: .public) \(detail, privacy: .public)") }
        return details ? text + "\n\n" + detail : text
    }

    private static func summary(_ error: Error) -> String {
        if let f = error as? PendingGroup.Failure {
            return f == .notReady ? String(localized: "Adding a computer is not ready yet.", bundle: .app) : String(localized: "No computers connected.", bundle: .app)
        }
        if let f = error as? PairingMember.Failure {
            if case .refused(.wrongCode) = f {
                return String(localized: "The code did not match. Run cbb pair on the computer again and scan the new code.", bundle: .app)
            }
            return String(localized: "The computer refused. Run cbb pair on it again.", bundle: .app)
        }
        if let f = error as? LiveGroup.Failure, f == .notConfirmed {
            return String(localized: "The computer joined but did not confirm it. Check cbb status on it.", bundle: .app)
        }
        if let f = error as? LiveGroup.Failure {
            switch f {
            case .noNetwork: return String(localized: "Connect this phone to your home Wi-Fi, then try again.", bundle: .app)
            case .timedOut: return String(localized: "No phone scanned the code in five minutes. Try again.", bundle: .app)
            case .tooManyWrongCodes: return String(localized: "Too many wrong codes. Try again with a new code.", bundle: .app)
            case .notAdmin: return String(localized: "Only an admin phone can do this.", bundle: .app)
            case .noWindow:
                return String(localized: "No computer is waiting for a phone. Run cbb pair -admin on the computer that created the group, then try again.", bundle: .app)
            case .twoWindows:
                return String(localized: "Two computers are waiting for a device at once. Close cbb pair on one of them, then try again.", bundle: .app)
            case .needsRoot:
                return String(localized: "This computer did not open its window for a phone. Run cbb pair -admin on the computer that created the group.", bundle: .app)
            case .noGroupComputer:
                return String(localized: "No computer of the group was found on this network. Turn one on and keep this phone on its network, then try again.", bundle: .app)
            case .noGroup:
                return String(localized: "This phone is in no group, so there is nothing to leave.", bundle: .app)
            case let .rootLeaves(others):
                let names = others.formatted(.list(type: .and))
                return String(localized: "This phone holds the group's root, and the group has other devices: \(names). Remove them first, or let an admin phone take the group over.", bundle: .app)
            default: break
            }
        }
        if let f = error as? Restore.Failure {
            switch f.kind {
            case .needsQR:
                return String(localized: "Scan the QR code of the recovery sheet: on a new phone the typed key is not enough. A computer of the group takes the typed key with cbb recovery.", bundle: .app)
            case .otherGroup: return String(localized: "The computers found on this network are of another group than the sheet.", bundle: .app)
            case .notTheKey: return String(localized: "This is not the group's recovery key now: the root phone removed it or made a new one.", bundle: .app)
            case .notAMember: return String(localized: "The computer's answer does not fit the group's records.", bundle: .app)
            }
        }
        if let f = error as? Piv.Failure {
            switch f.kind {
            case .noPIV: return String(localized: "This is not a YubiKey with PIV, or PIV is turned off on it.", bundle: .app)
            case .wrongPIN: return String(localized: "Wrong PIN. Tries left before the YubiKey blocks it: \(f.left).", bundle: .app)
            case .blocked: return String(localized: "The YubiKey's PIN is blocked. Unblock it with its PUK in Yubico Authenticator, then try again.", bundle: .app)
            case .managementKey:
                return String(localized: "This YubiKey's management key is not the factory one, so the app cannot put a key on it. Use the printed sheet instead.", bundle: .app)
            case .oldFirmware:
                return String(localized: "This YubiKey is older than firmware 5.7, which the app needs to put a key on it. Use the printed sheet instead.", bundle: .app)
            case .noFreeSlot: return String(localized: "This YubiKey has no free slot for the key.", bundle: .app)
            case .noKey: return String(localized: "This YubiKey holds no recovery key.", bundle: .app)
            case .card: return String(localized: "The YubiKey did not answer as expected. Hold it still to the phone and try again.", bundle: .app)
            }
        }
        if let f = error as? YubiKeyNfc.Failure {
            switch f {
            case .unavailable: return String(localized: "This iPhone cannot read a YubiKey over NFC.", bundle: .app)
            case .noCard: return String(localized: "No YubiKey was held to the phone. Try again.", bundle: .app)
            }
        }
        if let r = error as? LiveGroup.CommandRefused {
            return String(localized: "The computer refused: \(r.reason)", bundle: .app)
        }
        if let f = error as? MemberNode.Failure {
            switch f {
            case .notConnected: return String(localized: "The computer is not connected to this phone. Try again when it shows online.", bundle: .app)
            case .timedOut, .closed: return String(localized: "The computer did not answer. It may run an older version of CBB.", bundle: .app)
            case .muted: return String(localized: "An admin muted this phone, so its copies stay on it.", bundle: .app)
            default: break
            }
        }
        if let f = error as? Content.Failure, case .tooLarge = f {
            return String(localized: "This image is larger than 100 MB, so it stays on the computer.", bundle: .app)
        }
        if let f = error as? Content.Failure, f == .unread {
            return String(localized: "This copy was not sealed to this phone, so it cannot be read here. Copy it again on that device.", bundle: .app)
        }
        if error is CopyKeys.Failure {
            return String(localized: "This phone does not have the group's device list yet, so it cannot seal or read copies. Try again once a computer is connected.", bundle: .app)
        }
        if error is Content.Failure || (error as? MemberNode.Failure) == .missing {
            return String(localized: "Could not get the image from the computers. Copy it there again, then try again.", bundle: .app)
        }
        if error is LiveGroup.ClipboardUnreadable {
            return String(localized: "Could not read the clipboard, so it was left as it is. Allow pasting for CBB, or copy the text again.", bundle: .app)
        }
        if error is Arrangement.Refused {
            return String(localized: "The tiles stay as they were: that change does not fit.", bundle: .app)
        }
        if let f = error as? PhoneGroup.Failure, f == .cannotRemoveRoot {
            return String(localized: "The phone that made the group cannot be removed yet.", bundle: .app)
        }
        if let f = error as? PhoneGroup.Failure, f == .rootless {
            return String(localized: "This computer is installed without root, so any of its programs can read its keys. It can never be an admin.", bundle: .app)
        }
        if let f = error as? PhoneGroup.Failure, f == .belowKeyLevel {
            return String(localized: "The group's admin keys setting does not let this device's keys be an admin. Change it in Settings, Admin keys.", bundle: .app)
        }
        if let f = error as? PhoneGroup.Failure, f == .readsCopies {
            return String(localized: "An admin reads the copies, so it is a hub that reads them too, not one that only passes them on.", bundle: .app)
        }
        if let f = error as? PhoneGroup.Failure, f == .fileKey {
            return String(localized: "This computer keeps its keys in a file. Make it an admin first on its page, which warns what that means.", bundle: .app)
        }
        if error is PairingJoiner.Failure {
            return String(localized: "The other phone's group could not be joined. Try again.", bundle: .app)
        }
        if error is LiveGroup.Failure || error is TLSTransport.Failure {
            return String(localized: "Could not reach the computer. Is it on the same network as this phone, and does its firewall let CBB in?", bundle: .app)
        }
        return String(localized: "Something went wrong. Try again.", bundle: .app)
    }
}

/// Stands in for the group in previews and tests: no group, no computers.
@MainActor
final class PendingGroup: GroupController {
    enum Failure: Error { case notReady, noComputers }
    var hasGroup: Bool { false }
    var isAdmin: Bool { true }
    var computers: [AppModel.Computer] { [] }
    var devices: [AppModel.Computer] { [] }
    func prepare() throws {}
    func remove(_ id: String) async throws {}
    func makeAdmin(_ id: String) async throws {}
    func admit(_ code: JoinCode, retrying: @escaping @MainActor () -> Void) async throws { throw Failure.notReady }
    func join(show: @escaping @MainActor (JoinCode) -> Void) async throws { throw Failure.notReady }
    func sync(board: AppModel.Board?) async throws -> AppModel.SyncResult { throw Failure.noComputers }
    func refresh() async {}
}
