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
    /// The group's tag; nil without a group.
    var groupTag: String? { get }
    /// The device tiles as the member keeps them, with the user's change op
    /// applied first (docs/apps.md, "What the member shows"); nil while no
    /// member runs. A change that does not fit throws and changes nothing.
    func view(_ op: Arrangement.Op?) throws -> Arrangement.View<CoreMember.TileDevice>?
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
    /// The group's key level (Records.keyLevels) on the root phone; nil elsewhere.
    var keyLevel: String? { get }
    /// Sets the group's key level; only the root phone does.
    func setKeyLevel(_ level: String) async throws
    /// How long a copy and a secret live, in milliseconds (D-129).
    var ttlMS: (copy: Int64, secret: Int64) { get }
    /// Sets either, nil keeping it; the root and the admin phones do.
    func setTtl(ms: Int64?, secretMS: Int64?) async throws
    /// Unfreezes an admin computer that another admin froze.
    func unfreeze(_ id: String) async throws
    /// Freezes an admin computer, as one does with a stolen one.
    func freeze(_ id: String) async throws
    /// Makes an admin computer a hub through the project's forwarder (D-134).
    func makeHub(_ id: String) async throws
    /// Whether this phone holds the group's root.
    var isRoot: Bool { get }
    /// Whether the saved group was made before 0.6, which this version no
    /// longer runs (D-126): the app offers only Leave.
    var before06: Bool { get }
    /// Makes the key the paired watch made an admin key with the role
    /// watch; only the root phone does. Returns what the watch keeps.
    func addWatch(_ request: WatchState.KeyRequest) async throws -> WatchState.Admission
    /// What the group's watch may do to a device: nothing on 0.6 (D-124).
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
    /// Turns sync on this phone on, or off for forMS milliseconds, 0 for
    /// until turned on again; needs no rights.
    func setSync(_ on: Bool, forMS: Int64) throws
    /// Mutes a device for the group for forMS milliseconds, 0 for until it
    /// is unmuted, or unmutes it; only an admin phone does.
    func setMuted(_ id: String, _ on: Bool, forMS: Int64) async throws
    /// Puts text where a computer's focus is; only an admin phone does.
    func paste(_ id: String, text: String, method: String, enter: Bool, secret: Bool) async throws
    /// Pastes a picture or files where a computer's focus is; only an admin phone does.
    func pasteMedia(_ id: String, parts: [CoreMember.Part], enter: Bool) async throws
    /// Runs a quick action on a device; only an admin phone does.
    func runAction(_ id: String, name: String) async throws
    /// Turns every quick action off on a device; only an admin phone does.
    func actionsOff(_ id: String) async throws
    /// Joins a group from afar by a remote invitation the user accepted;
    /// shown gets the fingerprint the inviting admin compares.
    func joinByInvite(_ text: String, shown: @escaping @MainActor (String) -> Void) async throws
    /// The one button (D-128): swaps what the phone holds, board or the
    /// clipboard read, with the group's copy.
    func sync(board: AppModel.Board?) async throws -> AppModel.SyncResult
    /// The app's opening (D-128): sends a clipboard changed since the app
    /// last saw it, when it may read it, or takes the group's copy; nil
    /// when nothing went either way.
    func opened(mayRead: Bool) async throws -> AppModel.SyncResult?
    /// Copy on Home's last received line; nil when a newer copy came.
    func copyReceived(_ id: String) async throws -> AppModel.SyncResult?
    /// Updates which computers are online.
    func refresh() async
    /// Sync away from home: whether it is on, where it stands and its last
    /// failure; nil without a group.
    func awayStatus() async -> (on: Bool, status: AwayFromHome.Status, error: Error?, hub: String?, hubs: [String])?
    /// Turns sync away from home on or off.
    func setAwayFromHome(_ on: Bool) async throws
    /// Tells the group whether the app is in front.
    func setForeground(_ on: Bool)
    /// The app went to the background (true) or came back from it.
    func setBackground(_ on: Bool)
    /// One pass of the background refresh begins (true) or ends: the
    /// member connects for it, and lets go again after.
    func backgroundPass(_ running: Bool)
    /// Opens a remote invitation through a hub of the group, for a device
    /// far away; ask asks the user about the device that uses it, ended gets
    /// its name or why it ended without one.
    func invite(lifetime: Int, ask: @escaping @MainActor (CorePairing.Inviting.Request) async -> Bool,
                ended: @escaping @MainActor (Result<String, Error>) -> Void) async throws -> AppModel.Invitation
    /// The phone at a blind relay; nil without a group.
    func relayStatus() async -> AppModel.BlindRelay?
    /// Meets the group at a blind relay; both empty leave it.
    func setRelay(address: String, pin: String) async throws
    /// Why the phone does not sync, the reason that stops the most first.
    func why() async -> [WhyReason]
    /// The member's notices about the group (docs/apps.md, "Notices"),
    /// newest first.
    var notices: [Notice] { get }
    /// Hides a notice until something about it changes.
    func dismissNotice(_ id: String) async throws
    /// The last change of the group's root the member told of, until the
    /// person has seen it.
    var rootChanged: AppModel.RootChange? { get }
    /// The person saw the change of root.
    func rootChangeSeen()
    /// Who stays after moving the group's root to this phone with the
    /// recovery key, before anything is signed; leaveOut are the devices
    /// the person unticked.
    func changePreview(_ recovery: RecoveryInput, leaveOut: [String]) async throws -> ChangePreview
    /// Moves the group's root to this phone with the recovery key: a new
    /// root key in the Secure Enclave, Face ID, and leaveOut removed in the
    /// same act; overWaiting writes over a change whose records never came.
    func changeRoot(_ recovery: RecoveryInput, leaveOut: [String], overWaiting: Bool) async throws
    /// Makes a group on this phone and returns its recovery sheet, which
    /// the app shows once.
    func newGroup() async throws -> Core.RecoverySheet
    /// Opens the group's home window: shown gets its QR code and
    /// six digits; returns the name of the device that joined.
    func openWindow(shown: @escaping @MainActor (_ qr: String, _ digits: String) -> Void) async throws -> String
    /// Joins a group by a window's QR code, or by the six digits
    /// typed from its screen (qr empty).
    func joinByWindow(_ qr: String, digits: String) async throws
}

extension GroupController {
    func newGroup() async throws -> Core.RecoverySheet { throw PendingGroup.Failure.notReady }
    func openWindow(shown: @escaping @MainActor (_ qr: String, _ digits: String) -> Void) async throws -> String {
        throw PendingGroup.Failure.notReady
    }
    func joinByWindow(_ qr: String, digits: String) async throws { throw PendingGroup.Failure.notReady }
    var notices: [Notice] { [] }
    func dismissNotice(_ id: String) async throws {}
    var rootChanged: AppModel.RootChange? { nil }
    func rootChangeSeen() {}
    func changePreview(_ recovery: RecoveryInput, leaveOut: [String]) async throws -> ChangePreview { throw LiveGroup.Failure.noGroup }
    func changeRoot(_ recovery: RecoveryInput, leaveOut: [String], overWaiting: Bool) async throws { throw LiveGroup.Failure.noGroup }
    /// A stand-in tag for the tests' and previews' groups.
    var groupTag: String? { hasGroup ? "group" : nil }
    func view(_ op: Arrangement.Op?) throws -> Arrangement.View<CoreMember.TileDevice>? { nil }
    func unfreeze(_ id: String) async throws {}
    func freeze(_ id: String) async throws { throw PhoneGroup.Failure.notAdmin }
    func makeHub(_ id: String) async throws { throw PhoneGroup.Failure.notAdmin }
    var removed: Bool { false }
    func leave() async throws { throw LiveGroup.Failure.noGroup }
    var isRoot: Bool { false }
    var before06: Bool { false }
    var keyLevel: String? { nil }
    func setKeyLevel(_ level: String) async throws { throw PhoneGroup.Failure.notRoot }
    var ttlMS: (copy: Int64, secret: Int64) { (Records.defaultTtlMS, Records.defaultSecretTtlMS) }
    func setTtl(ms: Int64?, secretMS: Int64?) async throws { throw PhoneGroup.Failure.notAdmin }
    func opened(mayRead: Bool) async throws -> AppModel.SyncResult? { nil }
    func copyReceived(_ id: String) async throws -> AppModel.SyncResult? { nil }
    func addWatch(_ request: WatchState.KeyRequest) async throws -> WatchState.Admission { throw PhoneGroup.Failure.notRoot }
    func watchActions(for id: String) -> [String] { [] }
    func watchBody(_ ask: WatchState.Ask) throws -> Data { throw PhoneGroup.Failure.notForWatch }
    func deliverFromWatch(_ signed: WatchState.Signed) async throws { throw PhoneGroup.Failure.notForWatch }
    func joinByInvite(_ text: String, shown: @escaping @MainActor (String) -> Void) async throws { throw PendingGroup.Failure.notReady }
    func rename(_ id: String, to name: String) async throws {}
    func setMode(_ id: String, to mode: String) async throws {}
    func setSync(_ on: Bool, forMS: Int64) throws {}
    func setMuted(_ id: String, _ on: Bool, forMS: Int64) async throws {}
    func paste(_ id: String, text: String, method: String, enter: Bool, secret: Bool) async throws {}
    func pasteMedia(_ id: String, parts: [CoreMember.Part], enter: Bool) async throws {}
    func runAction(_ id: String, name: String) async throws {}
    func actionsOff(_ id: String) async throws {}
    func awayStatus() async -> (on: Bool, status: AwayFromHome.Status, error: Error?, hub: String?, hubs: [String])? { nil }
    func setAwayFromHome(_ on: Bool) async throws {}
    func setForeground(_ on: Bool) {}
    func setBackground(_ on: Bool) {}
    func backgroundPass(_ running: Bool) {}
    func invite(lifetime: Int, ask: @escaping @MainActor (CorePairing.Inviting.Request) async -> Bool,
                ended: @escaping @MainActor (Result<String, Error>) -> Void) async throws -> AppModel.Invitation {
        throw CoreMember.Failure.notConnected
    }
    func relayStatus() async -> AppModel.BlindRelay? { nil }
    func setRelay(address: String, pin: String) async throws {}
    func why() async -> [WhyReason] { hasGroup ? [] : [WhyReason(code: "not_in_group", level: "stop")] }
}

/// What the app shows and does; the views only read it and call it.
@MainActor
final class AppModel: ObservableObject {
    /// The one model of the running app, which the Shortcuts action uses
    /// too.
    static let shared: AppModel = {
        #if DEBUG
        // The made-up group of the screenshots and Home's UI tests.
        if let showcase = ShowcaseGroup.requested() { return AppModel(group: showcase) }
        #endif
        return AppModel(group: LiveGroup(), notifies: true)
    }()

    enum Phase: Equatable { case start, joining, home }

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
        /// "member", "phone" or "watch".
        var role = "member"
        /// What a member can do: "admin", "dials" and "hub".
        var caps: [String] = []
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
        /// Sync is off on this phone, until when or until turned on; only on
        /// its own entry.
        var syncOff: Hold?

        /// Whether it is a member with the capability c.
        func can(_ c: String) -> Bool { role == "member" && caps.contains(c) }
    }

    /// A mute or sync turned off that holds: until when, nil for until it is
    /// lifted.
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

    /// Whether a device's tile shows it muted: the answer the group is
    /// waiting on, else its mute; for this phone, sync turned off.
    func shownMuted(_ d: Computer) -> Bool {
        if d.isSelf { return d.syncOff != nil }
        return pendingMute[d.id] ?? (d.muted != nil)
    }

    /// Whether this phone may mute the device from its tile: its own sync
    /// always, another device only as an admin.
    func mayMute(_ d: Computer) -> Bool { d.isSelf || isAdmin }

    /// Sync turned off on this phone; nil while it is on.
    var syncOff: Hold? { devices.first(where: \.isSelf)?.syncOff }

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
        /// The button sent what the phone held and took the group's copy
        /// (D-128): from the device that copied it, and the start of a text.
        case swapped(from: String?, preview: String?)
        case nothingNew
        /// Files a computer copied, saved in the app's folder in Files, or
        /// one image or video in Photos.
        case savedFiles(photos: Bool)

        /// The same result without the start of the text, for an answer
        /// that may show on a locked phone.
        var withoutPreview: SyncResult {
            if case .fetched(let from, _) = self { return .fetched(from: from, preview: nil) }
            if case .swapped(let from, _) = self { return .swapped(from: from, preview: nil) }
            return self
        }
    }

    @Published private(set) var phase: Phase
    @Published private(set) var computers: [Computer] = []
    @Published private(set) var devices: [Computer] = [] {
        didSet {
            loadTiles()
            SyncSwitch.publish(group.hasGroup ? syncOff == nil : nil)
            PushSetup.shared.group(tag: group.groupTag, me: devices.first(where: \.isSelf)?.id, devices: devices.map(\.id),
                                   root: devices.first(where: \.isRoot)?.id)
        }
    }
    /// The devices and collections, this phone among them, in the user's
    /// order as the member keeps it (docs/apps.md, "What the member
    /// shows"), and whether the user changed it.
    @Published private(set) var arranged: [Arranged] = []
    @Published private(set) var customOrder = false
    /// One line about the last action, in plain words.
    @Published var message: String?
    /// The mutes asked for and not yet answered, by device: the tile shows
    /// the new state at once and goes back only when the group refuses it.
    @Published private(set) var pendingMute: [String: Bool] = [:]
    /// The bug report to ask about in release mode ("Oops, something
    /// broke"); in debug mode a break shows whole in `message` instead.
    @Published private(set) var bug: BugReports.Offer?
    @Published private(set) var busy = false
    /// A remote invitation the user scanned, opened or pasted, which waits
    /// to be accepted or declined (docs/apps.md, Start).
    struct PendingInvite: Equatable, Identifiable {
        let text: String
        let invitation: Core.Invitation
        var id: String { text }
    }
    @Published var pendingInvite: PendingInvite?
    /// The invitation the join screen joins by, once accepted.
    @Published private(set) var joiningInvite: PendingInvite?
    /// The fingerprint this phone shows while it joins by an invitation.
    @Published private(set) var inviteFingerprint: String?
    @Published private(set) var isAdmin = true
    /// Whether this phone holds the group's root, which ends conflicts.
    @Published private(set) var isRoot = false
    /// The group's key level on the root phone; nil elsewhere.
    @Published private(set) var keyLevel: String?
    /// The member's notices about the group, newest first.
    @Published private(set) var notices: [Notice] = []
    /// A change of the group's root the person has not seen yet.
    @Published private(set) var rootChanged: RootChange?

    /// A change of the group's root, as the notice on every device shows
    /// it: the old and the new root's names, and the change's step.
    struct RootChange: Equatable, Sendable {
        var from: String
        var to: String
        var seq: UInt64
    }
    /// The saved group was made before 0.6 (D-126): the app shows that a
    /// new group is needed and offers Leave.
    @Published private(set) var before06 = false
    /// The group removed this phone; the app offers to leave.
    @Published private(set) var removed = false

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

    /// Whether d is one of the group's hubs, as this phone knows: a hub
    /// whose offer it keeps; nil otherwise.
    func hubMark(_ d: Computer) -> HubMark? {
        guard let a = away, a.on else { return nil }
        if a.hub == d.id, a.status == .connected || a.status == .atHome { return .inUse }
        return a.hubs.contains(d.id) ? .hub : nil
    }

    @Published private(set) var away: Away?
    /// What turning it on or off said, when it failed.
    @Published private(set) var awayNote: String?

    /// The phone at a blind relay as Settings shows it (docs/design.md,
    /// "Blind relay"): where it stands, why the relay does not take it, the
    /// relay, and the group's devices there and the connections through it.
    struct BlindRelay: Equatable {
        var status: RelayOnPhone.Status
        var error: String?
        var relay: HubState.Forwarder?
        var online = 0
        var through = 0
        /// Whether this phone sets the relay: on a group of 0.6 only the
        /// root does, for the whole group.
        var editable = true
        /// On the root phone of a group of 0.6: the group's server
        /// credentials expired, so the relay and the hubs' forwarders take
        /// nobody until the root key renews them.
        var periodOverdue = false
    }

    @Published private(set) var blindRelay: BlindRelay?
    /// What the last change to the relay said, when it failed.
    @Published private(set) var relayNote: String?
    /// The relay's last error, logged once.
    private var relayError: String?

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
        /// The invitation's text, for its QR code.
        var text: String
        var expires: Date
        var file: URL
        var request: CorePairing.Inviting.Request?
    }

    @Published private(set) var invite: Invite?
    /// How the last invitation ended, or why it did not open.
    @Published private(set) var inviteNote: String?
    private var invitation: Invitation?
    private var answer: CheckedContinuation<Bool, Never>?
    /// How long an invitation from the phone is valid: an hour, as cbb
    /// invite's default.
    static let inviteLifetime = 3600

    let group: GroupController
    private let defaults: UserDefaults
    /// The running app's model notifies of the group's events and tells the
    /// watch; the tests' and previews' do neither.
    private let notifies: Bool
    static let preparedKey = "prepared"

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
        loadTiles()
        if let live = group as? LiveGroup {
            live.onPanic = { [weak self] details, log in self?.broke(kind: "panic", code: 5, name: "panic", details: details, log: log) }
            live.onReceived = { [weak self] r in self?.received = r }
            let bugs = self.bugs
            Task.detached { bugs.resend() }
        }
    }

    // MARK: Bug reports

    /// The bug reports' state in the app's defaults, posted with URLSession.
    nonisolated let bugs = BugReports(
        load: { UserDefaults.standard.data(forKey: "BugState") },
        save: { UserDefaults.standard.set($0, forKey: "BugState") },
        post: AppModel.postBug
    )

    /// Something broke: in debug mode `message` shows it whole; in release
    /// mode the core's report is offered (asked, sent by itself when the
    /// user allowed always, or not made again).
    func broke(kind: String, code: Int, name: String, details: String, log lines: [String]) {
        log.error("\(kind, privacy: .public): \(details, privacy: .public)")
        let summary = String(localized: "Something in CBB broke. It started again.", bundle: .app)
        var i = BugReports.Input(kind: kind, code: code, name: name, message: "Something in CBB broke, and it started again.",
                                 details: details, app: "ios", version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "")
        i.build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? ""
        i.os = "ios"
        i.os_version = ProcessInfo.processInfo.operatingSystemVersionString
        i.model = Self.machine
        #if arch(arm64)
        i.arch = "arm64"
        #else
        i.arch = "x86_64"
        #endif
        i.log = lines
        i.names = devices.map(\.name)
        let bugs = self.bugs
        Task.detached {
            let offer = try? bugs.offer(i)
            await MainActor.run {
                if Self.showsErrorDetails {
                    self.message = summary + "\n\n" + details
                    return
                }
                switch offer?.action {
                case "ask": self.bug = offer
                case "send": if let offer { Task.detached { bugs.send(offer) } }
                default: self.message = summary
                }
            }
        }
    }

    /// The user allowed the report on screen, and maybe always; it goes in
    /// the background.
    func allowBug(always: Bool) {
        guard let o = bug else { return }
        bug = nil
        let bugs = self.bugs
        Task.detached {
            try? bugs.allow(always: always)
            bugs.send(o)
        }
    }

    /// The user cancelled the report: nothing goes.
    func cancelBug() { bug = nil }

    /// The device's model identifier, as iPhone17,1.
    nonisolated static var machine: String {
        var u = utsname()
        uname(&u)
        return withUnsafeBytes(of: &u.machine) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    }

    /// Posts a report's body and waits for the server's answer; throws when
    /// it did not go.
    nonisolated static func postBug(_ url: String, _ body: Data) throws -> Data {
        guard let u = URL(string: url) else { throw URLError(.badURL) }
        var r = URLRequest(url: u, timeoutInterval: 20)
        r.httpMethod = "POST"
        r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        r.httpBody = body
        let done = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var result: Result<Data, Error> = .failure(URLError(.timedOut))
        URLSession.shared.dataTask(with: r) { data, response, error in
            if let error {
                result = .failure(error)
            } else if (response as? HTTPURLResponse)?.statusCode != 200 {
                result = .failure(URLError(.badServerResponse))
            } else {
                result = .success(data ?? Data())
            }
            done.signal()
        }.resume()
        done.wait()
        return try result.get()
    }

    /// At the first launch: makes this phone's own key, once.
    func prepare() {
        guard phase == .start, !defaults.bool(forKey: Self.preparedKey) else { return }
        do {
            try group.prepare()
            defaults.set(true, forKey: Self.preparedKey)
        } catch {
            message = Self.describe(error)
        }
    }

    /// Opens the screen that joins a group, always as a member.
    func startJoining() {
        message = nil
        joiningInvite = nil
        phase = .joining
    }

    /// Reads a remote invitation the user scanned, opened or pasted, for
    /// the screen that accepts or declines it; false with a message when it
    /// is none, is another kind of device's, or the phone is in a group
    /// already. It carries no expiry: the hub refuses one whose time is over.
    func readInvitation(_ text: String) -> Bool {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard phase == .start else {
            message = String(localized: "This phone is in a group already. Leave it first to join another.", bundle: .app)
            return false
        }
        do {
            switch try Core.readInvite(text) {
            case let .refused(_, why):
                let summary = String(localized: "This is not a CBB invitation.", bundle: .app)
                message = Self.showsErrorDetails ? summary + "\n\n" + why : summary
                return false
            case let .invitation(inv):
                guard inv.phone else {
                    message = String(localized: "This invitation is for another kind of device. Ask for one for this phone.", bundle: .app)
                    return false
                }
                message = nil
                pendingInvite = PendingInvite(text: text, invitation: inv)
                return true
            }
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// The user declined the invitation: nothing is sent.
    func declineInvitation() { pendingInvite = nil }

    /// The user accepted the invitation: the join screen joins by it.
    func acceptInvitation() {
        guard let p = pendingInvite else { return }
        pendingInvite = nil
        message = nil
        joiningInvite = p
        phase = .joining
    }

    /// Joins by the accepted invitation: shows the fingerprint for the
    /// inviting admin to compare, then goes Home once admitted. The join
    /// screen runs it as its task, so leaving the screen cancels it.
    func joinByInvite() async {
        guard let p = joiningInvite else { return }
        do {
            try await group.joinByInvite(p.text) { [weak self] fp in self?.inviteFingerprint = fp }
            computers = group.computers
            devices = group.devices
            isAdmin = group.isAdmin
            joiningInvite = nil
            phase = .home
            message = String(localized: "This phone is in the group. It syncs through the group's hub away from home.", bundle: .app)
        } catch is CancellationError {
        } catch {
            message = Self.describe(error)
        }
        inviteFingerprint = nil
    }

    /// Leaves the join screen without joining.
    // MARK: Pairing on 0.6: the window and the joiner

    /// The recovery sheet of the group of 0.6 this phone just made, shown
    /// once until the person says it is kept.
    @Published var newSheet: Core.RecoverySheet?
    /// The open window's QR code and its six digits, while "Add a device"
    /// shows them.
    @Published private(set) var windowQr: String?
    @Published private(set) var windowDigits: String?

    private func endPairing() {
        windowQr = nil
        windowDigits = nil
    }

    /// "Add a device" on 0.6: makes the group first on a phone without one
    /// (its recovery sheet shows over the window), then opens the window
    /// until a device joins. The screen runs it as its task, so leaving it
    /// closes the window. Returns whether a device joined.
    ///
    /// A group made here takes the phone Home only once the window ends:
    /// Start shows this window, and leaving Start while it is open would
    /// close it the moment it opened.
    func addByWindow() async -> Bool {
        message = nil
        var made = false
        defer {
            endPairing()
            if made && phase == .start { phase = .home }
        }
        do {
            if !group.hasGroup {
                busy = true
                defer { busy = false }
                newSheet = try await group.newGroup()
                made = true
                await refresh()
                isAdmin = group.isAdmin
            }
            let name = try await group.openWindow { [weak self] qr, digits in
                self?.windowQr = qr
                self?.windowDigits = digits
            }
            log.info("\(name, privacy: .public) joined through this phone's window")
            await refresh()
            message = String(localized: "The device joined the group.", bundle: .app)
            return true
        } catch is CancellationError {
            return false
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// Joins a group of 0.6 by a window's scanned or pasted QR code, or by
    /// the six digits the person typed from the window's screen (the window
    /// is then found on the home network), then goes Home. The join screen
    /// runs it, so leaving it cancels it.
    func joinByWindow(_ text: String) async -> Bool {
        let qr = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let digits = qr.filter { !$0.isWhitespace }
        let typed = digits.count == 6 && digits.allSatisfy { $0.isASCII && $0.isNumber }
        guard typed || qr.hasPrefix(Self.windowQR) else {
            message = String(localized: "This is neither a pairing window's QR code nor its six digits. On a phone of the group, tap + to show them.", bundle: .app)
            return false
        }
        message = nil
        busy = true
        defer {
            busy = false
            endPairing()
        }
        do {
            try await group.joinByWindow(typed ? "" : qr, digits: typed ? digits : "")
            await refresh()
            // A member: the root makes it an admin later.
            isAdmin = group.isAdmin
            phase = .home
            return true
        } catch is CancellationError {
            return false
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// How the QR code of a pairing window of 0.6 starts (docs/protocol.md,
    /// section 7, "The window's QR code").
    static let windowQR = "cbb://pair?"

    func cancelJoin() {
        joiningInvite = nil
        inviteFingerprint = nil
        message = nil
        phase = .start
    }

    /// The one big button: the paste button hands over board; a button
    /// that is not one lets the app read the clipboard when it sends.
    func sync(board: Board? = nil, preview: Bool = true) async {
        busy = true
        defer { busy = false }
        do {
            let result = try await group.sync(board: board)
            message = Self.said(preview ? result : result.withoutPreview)
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
        case .swapped:
            return String(localized: "Sent.", bundle: .app)
        case .nothingNew:
            return String(localized: "Nothing new to send or fetch.", bundle: .app)
        case .savedFiles(photos: true):
            return String(localized: "Saved in Photos.", bundle: .app)
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

    /// Whether the app reads the clipboard by itself as it comes to the
    /// front: the user chose so on the paste note (PasteNote), "allow", or
    /// not, "later"; nil before the note was shown.
    static let pasteChoiceKey = "PasteChoice"
    var readsClipboard: Bool { UserDefaults.standard.string(forKey: Self.pasteChoiceKey) == "allow" }

    /// iOS refused the app the clipboard, or the user chose not to let the
    /// app read it: Home offers the system's paste button instead.
    @Published private(set) var pasteRefused = false

    /// The app's opening (D-128), while sync is on: a copy made since the
    /// app last saw the clipboard goes out, when the user let the app read
    /// it; otherwise the group's copy comes in. It never swaps, and says
    /// only what it did.
    func opened() async {
        guard group.hasGroup, syncOff == nil else { return }
        if !readsClipboard {
            pasteRefused = UserDefaults.standard.string(forKey: Self.pasteChoiceKey) != nil
        }
        do {
            if let result = try await group.opened(mayRead: readsClipboard) {
                if readsClipboard { pasteRefused = false }
                if result != .nothingNew {
                    message = Self.said(result)
                    if let message { Island.flash(message) }
                }
            }
        } catch is LiveGroup.ClipboardUnreadable {
            pasteRefused = true
        } catch {
            // No device connected yet, or the like: the next opening tries again.
        }
        computers = group.computers
    }

    /// The last copy that came from another device (D-128): from which
    /// device, its text, empty for a secret, which Home does not show, and
    /// when its lifetime runs out (D-129), after which Home hides it.
    struct Received: Equatable, Sendable {
        var id: String
        var from: String
        var text: String
        var until: Date
    }

    /// The last received copy, which Home shows with Copy.
    @Published var received: Received?

    /// Takes the last received line away when its lifetime ran out.
    func receivedExpired(_ id: String) {
        if received?.id == id { received = nil }
    }

    /// Copy on Home's last received line.
    func copyReceived() async {
        guard let r = received else { return }
        received = nil
        do {
            if let result = try await group.copyReceived(r.id) {
                message = Self.said(result)
            }
        } catch {
            message = Self.describe(error)
        }
    }

    /// Asks iOS for the clipboard once, so that Settings, CBB lists "Paste
    /// from Other Apps", then opens Settings there.
    func askForClipboard() async {
        UserDefaults.standard.set("allow", forKey: Self.pasteChoiceKey)
        _ = await Task.detached { UIPasteboard.general.hasStrings ? UIPasteboard.general.string : nil }.value
        if let url = URL(string: UIApplication.openSettingsURLString) {
            await UIApplication.shared.open(url)
        }
    }

    /// The user chose not to let the app read the clipboard for now.
    func declineClipboard() {
        UserDefaults.standard.set("later", forKey: Self.pasteChoiceKey)
        pasteRefused = true
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
        // Siri and the Shortcuts app may speak or show the answer on the
        // lock screen: it names the device, never the copy.
        await sync(board: text.map { Board(text: $0) }, preview: false)
        return message ?? ""
    }

    /// Hears of the group's events while iOS runs the app in the
    /// background for a moment (BackgroundRefresh): it waits up to wait for
    /// a computer to connect, then gives the records a moment to arrive.
    /// The clipboard stays as it is: iOS lets only the app in front read it.
    func refreshInBackground(wait: Duration = .seconds(20), records: Duration = .seconds(3)) async {
        group.backgroundPass(true)
        defer { group.backgroundPass(false) }
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
    /// Why the phone does not sync (docs/apps.md, "Why it does not sync").
    func why() async -> [WhyReason] { await group.why() }

    func refresh() async {
        await group.refresh()
        computers = group.computers
        devices = group.devices
        isRoot = group.isRoot
        before06 = group.before06
        removed = group.removed
        notices = group.notices
        rootChanged = group.rootChanged
        keyLevel = group.keyLevel
        (ttlMS, secretTtlMS) = group.ttlMS
        await refreshAway()
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
        // at home it is old news. The member logs each failure itself.
        let failing = a.status == .connecting ? a.error : nil
        if notifies { Notifier.shared.away(trying: a.on && failing != nil) }
        away = Away(on: a.on, status: a.status, error: failing.map {
            Self.describe($0, summary: String(localized: "The hub does not answer through the tunnel.", bundle: .app), log: false)
        }, hub: a.hub, hubs: a.hubs)
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
            (invitation, invite, inviteNote) = (inv, Invite(text: inv.text, expires: inv.expires, file: file), nil)
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
    private func ask(_ req: CorePairing.Inviting.Request) async -> Bool {
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
        // Push off in this group while the phone still reaches its members.
        PushSetup.shared.leaving()
        do {
            try await group.leave()
        } catch {
            message = Self.describe(error)
            PushSetup.shared.stayed()
            return false
        }
        PushSetup.shared.left()
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

    /// Hides a notice until something about it changes.
    func dismiss(notice: Notice) async {
        do {
            try await group.dismissNotice(notice.id)
        } catch {
            message = Self.describe(error)
        }
        notices = group.notices
    }

    /// The person saw the change of the group's root.
    func rootChangeSeen() {
        group.rootChangeSeen()
        rootChanged = nil
    }

    /// Who stays after moving the group's root to this phone; nil, with
    /// the message set, when the key does not fit or the member refuses.
    func changePreview(_ recovery: RecoveryInput, leaveOut: [String]) async -> ChangePreview? {
        do {
            return try await group.changePreview(recovery, leaveOut: leaveOut)
        } catch {
            message = Self.describe(error)
            return nil
        }
    }

    /// Moves the group's root to this phone; true once it is the root.
    func changeRoot(_ recovery: RecoveryInput, leaveOut: [String], overWaiting: Bool) async -> Bool {
        busy = true
        defer { busy = false }
        do {
            try await group.changeRoot(recovery, leaveOut: leaveOut, overWaiting: overWaiting)
            message = String(localized: "This phone is now the group's main device. The other devices hear of it as soon as they connect.", bundle: .app)
            await refresh()
            return true
        } catch {
            message = Self.describe(error)
            return false
        }
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

    /// Freezes a stolen admin computer: nothing it signs counts until the
    /// root unfreezes it.
    func freeze(_ id: String) async {
        do {
            try await group.freeze(id)
            message = String(localized: "Frozen.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        devices = group.devices
    }

    /// Makes an admin computer a hub with a hub command; the computer
    /// answers (D-134: a hub is never a phone).
    func makeHub(_ id: String) async {
        do {
            try await group.makeHub(id)
            message = String(localized: "It is a hub now.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        devices = group.devices
    }

    /// Turns sync on or off on a connected computer, as an admin.
    func setSync(_ id: String, on: Bool) async {
        do {
            try await group.setMode(id, to: on ? "shared" : "own")
            message = String(localized: "Sync is set.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        await group.refresh()
        devices = group.devices
    }

    /// Turns sync on this phone on, or off for forMS milliseconds, 0 for
    /// until turned on again (design.md, "Sync on and off").
    func turnSync(_ on: Bool, forMS: Int64 = 0) {
        do {
            try group.setSync(on, forMS: forMS)
            message = on
                ? String(localized: "Sync is on: copies go to the group and come from it.", bundle: .app)
                : String(localized: "Sync is off: the clipboard is this phone's own.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        devices = group.devices
    }

    /// Mutes a device for the whole group, or unmutes it.
    func setMuted(_ id: String, _ on: Bool, forMS: Int64 = 0) async {
        pendingMute[id] = on
        defer { pendingMute[id] = nil }
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

    /// Pastes a picture or files where a computer's focus is; true when it did.
    @discardableResult
    func pasteMedia(_ id: String, parts: [CoreMember.Part], enter: Bool) async -> Bool {
        do {
            try await group.pasteMedia(id, parts: parts, enter: enter)
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

    /// Whether a YubiKey is plugged into the USB-C port now (CryptoTokenKit).
    func yubiKeyPlugged() async -> Bool { await YubiKeyUsb.pluggedSlot() != nil }

    /// Seals the recovery sheet just made onto a YubiKey plugged in or held
    /// to the phone (CryptoTokenKit or Core NFC; docs/protocol.md, "The
    /// recovery key on a YubiKey (0.6)"), after its PIN, into the first empty
    /// retired slot for group. Sealing needs no touch. True once the card
    /// holds it.
    func sealOnCard(sheet: String, pin: String, group: String) async -> Bool {
        do {
            let sealed = try await YubiKeys.withCard(
                prompt: String(localized: "Hold the YubiKey to the top of the phone.", bundle: .app),
                done: String(localized: "The recovery key is on the YubiKey.", bundle: .app),
                plugged: { self.message = String(localized: "Writing to the YubiKey. Keep it plugged in until it is done.", bundle: .app) }
            ) { (card: SmartCard) throws -> RecoveryCard.Sealed in
                try RecoveryCard.seal(card, pin: pin, sheet: sheet, group: group)
            }
            message = String(localized: "The recovery key is on the YubiKey. The YubiKey and the sheet hold the same key: keep both, in different places.", bundle: .app)
            log.info("yubikey: sealed in slot \(String(sealed.slot, radix: 16), privacy: .public), factory management key \(sealed.defaultKey, privacy: .public)")
            return true
        } catch is CancellationError {
            return false
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// Opens the recovery secret on a YubiKey held to the phone, after its
    /// PIN and a touch, for one change of root; nil when it did not.
    func openCard(pin: String) async -> Data? {
        guard let group = group.groupTag else {
            message = Self.describe(LiveGroup.Failure.noGroup)
            return nil
        }
        do {
            let secret = try await YubiKeys.withCard(
                prompt: String(localized: "Hold the YubiKey with the recovery key to the top of the phone.", bundle: .app),
                done: String(localized: "The YubiKey opened the recovery key.", bundle: .app),
                plugged: { self.message = String(localized: "Touch the YubiKey when it blinks, and keep it plugged in until this message goes.", bundle: .app) }
            ) { (card: SmartCard) throws -> Data in
                try RecoveryCard.open(card, pin: pin, group: group)
            }
            message = nil
            return secret
        } catch is CancellationError {
            message = nil
            return nil
        } catch {
            message = Self.describe(error)
            return nil
        }
    }

    /// How long a copy and a secret live, in milliseconds (D-129).
    @Published private(set) var ttlMS = Records.defaultTtlMS
    @Published private(set) var secretTtlMS = Records.defaultSecretTtlMS

    /// Sets how long a copy (ms) or a secret (secretMS) lives, the other
    /// nil to keep it.
    func setTtl(ms: Int64?, secretMS: Int64?) async {
        do {
            try await group.setTtl(ms: ms, secretMS: secretMS)
            message = String(localized: "Saved. Every device of the group follows it.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        (ttlMS, secretTtlMS) = group.ttlMS
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

    /// Draws the member's tiles for the devices the group lists: the
    /// group's order, this phone first, while no member answers.
    private func loadTiles() {
        guard group.hasGroup, let v = try? group.view(nil) else {
            arranged = (devices.filter(\.isSelf) + devices.filter { !$0.isSelf }).map { .device($0) }
            customOrder = false
            return
        }
        show(v)
    }

    /// Shows the member's view: its tiles, each device as the group lists it.
    private func show(_ v: Arrangement.View<CoreMember.TileDevice>) {
        let byID = Dictionary(devices.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        arranged = v.tiles.compactMap { t in
            switch t {
            case .device(let d): byID[d.id].map { .device($0) }
            case let .collection(id, name, ds):
                .collection(Arrangement.Collection(id: id, name: name, devices: ds.map(\.id)), ds.compactMap { byID[$0.id] })
            }
        }
        customOrder = v.custom
    }

    /// Makes a change to the tiles, which the member keeps; one that does
    /// not fit leaves them as they were and says so.
    @discardableResult
    func arrange(_ op: Arrangement.Op) -> Bool {
        do {
            guard let v = try group.view(op) else { return false }
            show(v)
            return true
        } catch {
            message = Self.describe(error, summary: String(localized: "The tiles stay as they were: that change does not fit.", bundle: .app))
            return false
        }
    }

    /// Makes a collection of the devices and returns its ID; nil when it
    /// does not fit (a name too long, too many collections).
    func newCollection(_ name: String, devices ids: [String]) -> String? {
        let before = Set(collectionIDs)
        guard arrange(.new(name: name, devices: ids)) else { return nil }
        return collectionIDs.first { !before.contains($0) }
    }

    private var collectionIDs: [String] {
        arranged.compactMap { item -> String? in
            guard case let .collection(c, _) = item else { return nil }
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
        if let f = error as? CorePairing.Failure {
            if f.wrongCode {
                return String(localized: "The code did not match. Scan the device's code again.", bundle: .app)
            }
            if f.message.contains("add it as an admin") {
                return String(localized: "This phone asks to join as an admin, which only the group's main device can grant. Scan it with the main device, or join on it without asking to be an admin.", bundle: .app)
            }
            return String(localized: "The device refused to join. Try again on it.", bundle: .app)
        }
        if let f = error as? LiveGroup.Failure {
            switch f {
            case .noNetwork: return String(localized: "Connect this phone to your home Wi-Fi, then try again.", bundle: .app)
            case .timedOut: return String(localized: "No phone scanned the code in five minutes. Try again.", bundle: .app)
            case .notAdmin: return String(localized: "Only an admin phone can do this.", bundle: .app)
            case .noWindow:
                return String(localized: "No device of your group shows six digits on this network. On a phone of the group, tap +, or on a computer choose Add a device, then try again.", bundle: .app)
            case .twoWindows:
                return String(localized: "Two devices of your group show six digits at once. Close Add a device on one of them, then try again.", bundle: .app)
            case .needsRoot:
                return String(localized: "Only the group's main device sets the group's relay.", bundle: .app)
            case .noGroup:
                return String(localized: "This phone is in no group, so there is nothing to leave.", bundle: .app)
            case .hubUnreachable:
                return String(localized: "The group's hub did not answer. Check that the invitation is still valid and that the hub is on, then try again.", bundle: .app)
            case let .rootLeaves(others):
                let names = others.formatted(.list(type: .and))
                return String(localized: "This phone is the group's main device, and the group has other devices: \(names). Remove them first, or let an admin phone move the group to itself.", bundle: .app)
            default: break
            }
        }
        if let f = error as? RecoveryCard.Failure {
            let shown: String
            switch f.kind {
            case .wrongPIN: shown = String(localized: "Wrong PIN. Tries left before the YubiKey blocks it: \(f.left).", bundle: .app)
            case .blocked: shown = String(localized: "The YubiKey's PIN is blocked. Unblock it with its PUK in Yubico Authenticator, then try again.", bundle: .app)
            case .oldFirmware: shown = String(localized: "This YubiKey is older than firmware 5.3, which the recovery key needs. Use the printed sheet instead.", bundle: .app)
            case .noKey: shown = String(localized: "This YubiKey holds no recovery key.", bundle: .app)
            case .holdsOne: shown = String(localized: "This YubiKey holds this group's recovery key already.", bundle: .app)
            case .noFreeSlot: shown = String(localized: "Every place for keys on this YubiKey is in use. Use another YubiKey or the sheet.", bundle: .app)
            case .twoSlots: shown = String(localized: "This YubiKey holds two recovery keys for this group. Use the sheet instead.", bundle: .app)
            case .managementKey: shown = String(localized: "The app cannot use this YubiKey's management key. Use the printed sheet instead.", bundle: .app)
            case .card: shown = String(localized: "The YubiKey did not answer as expected. Hold it still to the phone and try again.", bundle: .app)
            }
            return Self.showsErrorDetails ? shown + "\n\n" + f.description : shown
        }
        if let f = error as? YubiKeyNfc.Failure {
            switch f {
            case .unavailable: return String(localized: "This iPhone cannot read a YubiKey over NFC. Plug the YubiKey into the USB-C port, or use the printed sheet.", bundle: .app)
            case .noCard: return String(localized: "No YubiKey was held to the phone or plugged in. Try again.", bundle: .app)
            }
        }
        if let r = error as? LiveGroup.CommandRefused {
            return String(localized: "The computer refused: \(r.reason)", bundle: .app)
        }
        if let f = error as? CoreMember.Failure {
            switch f {
            case .notConnected: return String(localized: "The computer is not connected to this phone. Try again when it shows online.", bundle: .app)
            case .timedOut: return String(localized: "The computer did not answer. It may run an older version of CBB.", bundle: .app)
            case .muted: return String(localized: "An admin muted this phone, so its copies stay on it.", bundle: .app)
            case .gone: break
            }
        }
        if let f = error as? Content.Failure, case .tooLarge = f {
            return String(localized: "This image is larger than 100 MB, so it stays on the computer.", bundle: .app)
        }
        if let f = error as? Content.Failure, f == .unread {
            return String(localized: "This copy was not sealed to this phone, so it cannot be read here. Copy it again on that device.", bundle: .app)
        }
        if error is Content.Failure || (error as? CoreMember.Failure) == .gone {
            return String(localized: "Could not get the image from the computers. Copy it there again, then try again.", bundle: .app)
        }
        if error is LiveGroup.ClipboardUnreadable {
            return String(localized: "Could not read the clipboard, so it was left as it is. Allow pasting for CBB, or copy the text again.", bundle: .app)
        }
        if let f = error as? PhoneGroup.Failure, f == .rootless {
            return String(localized: "This computer is installed without root, so any of its programs can read its keys. It can never be an admin.", bundle: .app)
        }
        if let f = error as? PhoneGroup.Failure, f == .belowKeyLevel {
            return String(localized: "The group's admin keys setting does not let this device's keys be an admin. Change it in Settings, Admin keys.", bundle: .app)
        }
        if let f = error as? PhoneGroup.Failure, f == .fileKey {
            return String(localized: "This computer keeps its keys in a file. Make it an admin first on its page, which warns what that means.", bundle: .app)
        }
        if error is LiveGroup.Failure {
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
    func sync(board: AppModel.Board?) async throws -> AppModel.SyncResult { throw Failure.noComputers }
    func refresh() async {}
}
