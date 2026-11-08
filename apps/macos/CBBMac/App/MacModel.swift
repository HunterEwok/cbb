// SPDX-License-Identifier: AGPL-3.0-only

import AppKit
import os
import SwiftUI

private let log = Logger(subsystem: "tools.cbb.mac", category: "app")

/// What the app knows of the service on this Mac: its status and the
/// group's devices, read from the control socket every few seconds. The
/// clipboard itself syncs without the app, through the pasteboard agent.
@MainActor
final class MacModel: ObservableObject {
    @Published private(set) var status: Control.Status?
    @Published private(set) var devices: [Control.Device] = [] {
        didSet { loadArrangement() }
    }
    /// The user's order of the tiles and their collections (docs/apps.md,
    /// "Collections and the order of the tiles"); nil outside a group.
    @Published private(set) var arrangement: Arrangement?
    /// Why the service cannot be reached; nil while it answers.
    @Published private(set) var problem: String?
    /// The outcome of the last action, for a line under it.
    @Published var message: String?
    @Published private(set) var busy = false
    /// Whether a join of a phone's group runs (JoinSheet), and its QR code
    /// once cbb wrote it.
    @Published private(set) var joining = false
    @Published private(set) var join: JoinCode?
    private var joinFile: URL?
    private var joinCancelled = false
    /// Whether macOS lets the app press keys for remote paste.
    @Published private(set) var pasteAllowed = Injector.allowed

    private let defaults: UserDefaults
    private let client = ControlClient()
    private let pasteTarget = PasteTarget()
    private var timer: Timer?

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    var inGroup: Bool { status?.group?.isEmpty == false && status?.removed != true }
    var this: Control.Device? { devices.first { $0.isSelf } }
    var others: [Control.Device] { devices.filter { !$0.isSelf } }
    var isAdmin: Bool { this?.admin == true }
    var isRoot: Bool { this?.root == true }
    var awayOn: Bool { status?.away != nil }

    /// The menu bar's image, a template from the asset catalog (drawn by
    /// tools/icon): the plain glyph without a group or with a problem, the
    /// group's mark in one, filled while another device is online.
    var trayImage: String {
        if problem != nil || !inGroup { return "Tray" }
        return others.contains { $0.online } ? "TrayOnline" : "TrayGroup"
    }

    func start() {
        guard timer == nil else { return }
        pasteTarget.start()
        Task { await refresh() }
        timer = Timer.scheduledTimer(withTimeInterval: 4, repeats: true) { [weak self] _ in
            Task { await self?.refresh() }
        }
        // Back from System Settings: show the leave to press keys at once.
        NotificationCenter.default.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.pasteAllowed = Injector.allowed }
        }
    }

    func refresh() async {
        pasteAllowed = Injector.allowed
        do {
            let (answer, _) = try await client.request(.init(op: "status"))
            var list: [Control.Device] = []
            if let st = answer.status, st.group?.isEmpty == false, st.removed != true {
                list = try await client.request(.init(op: "devices")).0.devices ?? []
            }
            show(status: answer.status, devices: list)
            problem = nil
        } catch {
            problem = Self.describe(error)
        }
    }

    /// Shows what the service said: its status, then the group's devices.
    func show(status: Control.Status?, devices: [Control.Device]) {
        self.status = status
        self.devices = devices
    }

    /// A tile below this Mac's: a device, or a collection with its devices
    /// as the group lists them.
    enum Arranged: Identifiable, Equatable {
        case device(Control.Device)
        case collection(Arrangement.Collection, [Control.Device])

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

    /// The devices and collections, this Mac among them, in the user's
    /// order: the group's order, this Mac first, until the user changes it.
    var arranged: [Arranged] {
        guard let a = arrangement else { return ((this.map { [$0] } ?? []) + others).map { .device($0) } }
        let byID = Dictionary(devices.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        return a.view(devices: devices.map(\.id), self: this?.id).compactMap { item in
            switch item {
            case .device(let id): byID[id].map { .device($0) }
            case .collection(let c): .collection(c, c.devices.compactMap { byID[$0] })
            }
        }
    }

    /// The collection with the ID, as the window shows it.
    func collection(_ id: String) -> (Arrangement.Collection, [Control.Device])? {
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
    /// devices that left once the list is whole: the group loaded, this Mac
    /// in it. Until the user changes something nothing is stored.
    private func loadArrangement() {
        guard inGroup, let tag = status?.group else {
            if arrangement != nil { arrangement = nil }
            return
        }
        var a = Arrangement.decode(defaults.data(forKey: Self.arrangementKey), group: tag)
        if let current = arrangement, current.group == tag { a = current }
        if this != nil, defaults.data(forKey: Self.arrangementKey) != nil {
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
            try a.apply(op, devices: devices.map(\.id), self: this?.id)
        } catch {
            message = Self.describe(error)
            return false
        }
        defaults.set(a.encoded(), forKey: Self.arrangementKey)
        arrangement = a
        return true
    }

    /// Asks macOS to let the app press keys for remote paste.
    func allowPaste() {
        Injector.askLeave()
        pasteAllowed = Injector.allowed
    }

    /// Sends what the pasteboard holds to the group, as a copy on this Mac.
    func send() async {
        guard let text = NSPasteboard.general.string(forType: .string), !text.isEmpty else {
            message = String(localized: "The clipboard holds no text.")
            return
        }
        await act {
            _ = try await self.client.request(.init(op: "copy"), payload: Data(text.utf8))
            return String(localized: "Sent to the group.")
        }
    }

    /// Puts the group's latest text into the pasteboard.
    func fetch() async {
        await act {
            let (_, body) = try await self.client.request(.init(op: "paste"))
            guard !body.isEmpty else { return String(localized: "The group has no text yet.") }
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(String(decoding: body, as: UTF8.self), forType: .string)
            return String(localized: "Fetched from the group.")
        }
    }

    func rename(_ id: String, to name: String) async {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return }
        await admin(["rename", id, name], done: String(localized: "Renamed."))
    }

    func remove(_ id: String) async { await admin(["remove", id], done: String(localized: "Removed from the group.")) }
    /// The dialog that asks first warns that the computer's key is a file,
    /// which -allow-file-key consents to.
    func makeAdmin(_ id: String) async { await admin(["admin", "-allow-file-key", id], done: String(localized: "It is an admin now.")) }
    /// Takes this Mac out of its group (cbb leave, D-83): its keys and the
    /// group's files go, its settings stay, and it may join again.
    func leave() async { await admin(["leave", "-yes"], done: String(localized: "Left the group. This Mac can join a group again.")) }
    func freeze(_ id: String) async { await admin(["freeze", id], done: String(localized: "Frozen.")) }
    /// Makes a device a hub of the group for sync away from home, reached
    /// through the project's forwarder: this Mac as cbb global hub does, or
    /// another computer, to which cbb sends a signed hub command. This Mac
    /// turns sync away from home on with it where it is off, after the
    /// question the app showed, which cbb asks again. A hub that reads the
    /// copies is an admin; with forwardOnly a computer that is no admin
    /// becomes a hub that only passes them on and reads none.
    func makeHub(_ d: Control.Device, forwardOnly: Bool = false) async {
        if !d.isSelf, forwardOnly {
            await admin(["global", "hub", "-on", d.id, "-forward-only"],
                        done: String(localized: "It is a hub now that only passes the copies on, and reads none of them."))
            return
        }
        let turnOn = d.isSelf && !awayOn
        var args = d.isSelf ? ["global", "hub", "-firewall", "no"] : ["global", "hub", "-on", d.id]
        if turnOn { args.insert("-away-on", at: 2) }
        await admin(args, answer: turnOn, done: String(localized: "It is a hub now."))
    }
    /// Makes a hub stop being one: this Mac, or another device, to which
    /// cbb sends a signed hub command. Its clients go to the next hub; the
    /// app warned first when there is none.
    func stopHub(_ d: Control.Device) async {
        let args = d.isSelf ? ["global", "hub", "off", "-yes"] : ["global", "hub", "off", "-on", d.id, "-yes"]
        await admin(args, done: String(localized: "It is no hub any more."))
    }
    /// Whether the group has a hub other than d that this Mac knows of.
    func otherHub(than d: Control.Device) -> Bool {
        devices.contains { $0.id != d.id && $0.hub }
    }
    /// How a hub's tunnel hides: plain WireGuard, AmneziaWG or VLESS.
    enum HubTunnel: String, CaseIterable, Identifiable {
        case plain, obfuscate, vless
        var id: String { rawValue }
        var title: String {
            switch self {
            case .plain: "WireGuard"
            case .obfuscate: "AmneziaWG"
            case .vless: "VLESS"
            }
        }
    }

    /// How this Mac's tunnel hides while it is a hub.
    var hubTunnel: HubTunnel {
        guard let a = status?.away else { return .plain }
        return a.vless == true ? .vless : a.obfuscated == true ? .obfuscate : .plain
    }

    /// Sets how this hub's tunnel hides and, with forwarder, its forwarder
    /// ("default" for the project's), keeping its addresses and port.
    func setHub(_ tunnel: HubTunnel, forwarder: String? = nil, key: String? = nil) async {
        var args = ["global", "hub", "-keep", "-firewall", "no"]
        switch tunnel {
        case .plain: break
        case .obfuscate: args.append("-obfuscate")
        case .vless: args.append("-vless")
        }
        if let forwarder, !forwarder.isEmpty {
            args += ["-forwarder", forwarder]
            if let key, !key.isEmpty { args += ["-forwarder-key", key] }
        }
        await admin(args, done: String(localized: "The hub's settings are saved."))
    }

    /// On the group's root: voids both histories of every key that signed two.
    func resolve() async {
        await admin(["resolve"], done: String(localized: "Both histories are void. The device signs its records again by itself."))
    }
    func unfreeze(_ id: String) async { await admin(["unfreeze", id], done: String(localized: "Unfrozen.")) }

    /// Turns sync on or off: this Mac's with id nil, or on an admin another
    /// device's, which cbb sends it as a signed command.
    func setMode(_ mode: SyncMode, on id: String? = nil) async {
        guard let id else { return await turnSync(mode == .shared) }
        await admin(["sync", "-on", id, mode == .shared ? "on" : "off"], done: String(localized: "Sync is set."))
    }

    /// Turns sync away from home on or off; on needs the user's yes to the
    /// warning the app showed, which cbb asks for.
    func setAway(_ on: Bool) async {
        await admin(["global", on ? "on" : "off"], answer: on, done: on ? String(localized: "Sync away from home is on.") : String(localized: "Sync away from home is off."))
    }

    /// Whether sync is off on this Mac now, and until when, nil for until
    /// it is turned on again.
    var syncOff: Bool { status?.mode == SyncMode.own.rawValue }
    var syncOffUntil: Date? { Self.date(ms: status?.syncUntilMS) }
    /// Whether an admin muted this Mac, and until when.
    var muted: Bool { status?.muted == true }
    var mutedUntil: Date? { Self.date(ms: status?.mutedUntilMS) }

    nonisolated static func date(ms: Int64?) -> Date? {
        guard let ms, ms > 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
    }

    /// Turns this Mac's sync on, or off for forMS milliseconds, 0 for until
    /// turned on again: the clipboard is then this Mac's own. Any user of
    /// the Mac may, over the plain socket.
    func turnSync(_ on: Bool, forMS: Int64 = 0) async {
        var h = Control.Header(op: "sync", name: on ? "on" : "off")
        if !on, forMS > 0 { h.forMS = forMS }
        await act {
            _ = try await self.client.request(h)
            return on ? String(localized: "Sync is on here: copies go to the group and come from it.") : String(localized: "Sync is off here: the clipboard is this Mac's own.")
        }
    }

    /// On an admin: mutes a device for the whole group, for forMS
    /// milliseconds, 0 for until an admin unmutes it; its copies then stay
    /// its own.
    func mute(_ id: String, forMS: Int64 = 0) async {
        var arguments = ["mute", "-on", id]
        if forMS > 0 { arguments += ["-for", "\(forMS)ms"] }
        await admin(arguments, done: String(localized: "Muted: its copies do not reach the group."))
    }

    func unmute(_ id: String) async {
        await admin(["unmute", "-on", id], done: String(localized: "Unmuted: its copies reach the group again."))
    }

    /// What cbb pair -app writes (cmd/cbb/joinapp.go), with when the wait
    /// ends.
    struct JoinCode: Decodable, Equatable {
        let qr: String
        let expires: Int
        let port: Int
        var ends = Date()

        private enum CodingKeys: String, CodingKey { case qr, expires, port }
    }

    /// Joins the group of the phone that scans the QR code: cbb runs as the
    /// administrator and writes the code into a file the app made, which
    /// the app reads while cbb waits; cancelJoin removes the file.
    func joinPhone() async {
        guard !joining, !busy else { return }
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-join-\(UUID().uuidString).json")
        guard FileManager.default.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            message = Self.describe(Admin.Failure.failed(String(localized: "The app could not make the file for the QR code."), detail: file.path))
            return
        }
        joining = true
        joinFile = file
        joinCancelled = false
        let poll = Task { [weak self] in
            while !Task.isCancelled {
                if let data = try? Data(contentsOf: file), var code = try? JSONDecoder().decode(JoinCode.self, from: data) {
                    code.ends = Date().addingTimeInterval(TimeInterval(code.expires))
                    self?.join = code
                    return
                }
                try? await Task.sleep(for: .milliseconds(300))
            }
        }
        let details = Self.showsErrorDetails
        await act { [weak self] in
            do {
                _ = try await Admin.run(["pair", "-app", file.path], details: details)
            } catch {
                if self?.joinCancelled == true { throw Admin.Failure.cancelled }
                throw error
            }
            return String(localized: "Joined the group.")
        }
        poll.cancel()
        try? FileManager.default.removeItem(at: file)
        joinFile = nil
        join = nil
        joining = false
    }

    /// Ends the wait for the phone: cbb sees its file gone and hangs up.
    func cancelJoin() {
        guard let file = joinFile else { return }
        joinCancelled = true
        try? FileManager.default.removeItem(at: file)
    }

    /// Admits the device whose QR code says text, such as a phone with
    /// Aurora OS or Sailfish OS that waits: cbb pair -qr as the
    /// administrator, the text on its standard input; with asAdmin, on the
    /// group's root, a phone that asks to be an admin becomes one.
    func admitByQR(_ text: String, asAdmin: Bool = false) async {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.isWaitingJoiner(text) else {
            message = String(localized: "This QR code is not of a device that waits to join.")
            return
        }
        await admin(["pair", "-qr"] + (asAdmin ? ["-admin"] : []), input: text + "\n", done: String(localized: "It joined the group."))
    }

    /// Whether text is the QR code of a device that listens for the member
    /// that admits it (docs/protocol.md, section 6): a code, an address and
    /// a fingerprint.
    nonisolated static func isWaitingJoiner(_ text: String) -> Bool {
        guard let c = URLComponents(string: text), c.scheme?.lowercased() == "cbb", c.host?.lowercased() == "join" else { return false }
        let items = c.percentEncodedQueryItems ?? []
        func has(_ name: String) -> Bool { items.contains { $0.name == name && !($0.value ?? "").isEmpty } }
        return has("code") && has("addr") && has("fp")
    }

    private func admin(_ arguments: [String], answer: Bool = false, input: String? = nil, done: String) async {
        let details = Self.showsErrorDetails
        await act {
            _ = try await Admin.run(arguments, answer: answer, input: input, details: details)
            return done
        }
    }

    private func act(_ work: @escaping () async throws -> String) async {
        busy = true
        defer { busy = false }
        do {
            message = try await work()
        } catch Admin.Failure.cancelled {
            message = nil
        } catch {
            message = Self.describe(error)
        }
        await refresh()
    }

    /// Whether a message names the error underneath, to find out what
    /// failed: on in debug builds, off in release ones, and either way the
    /// ShowErrorDetails default when it is set (Settings, or
    /// defaults write tools.cbb.mac ShowErrorDetails -bool YES).
    nonisolated static var showsErrorDetails: Bool {
        // bool(forKey:) reads YES and NO given as text too, as a launch
        // argument (-ShowErrorDetails NO) gives them.
        if UserDefaults.standard.object(forKey: "ShowErrorDetails") != nil { return UserDefaults.standard.bool(forKey: "ShowErrorDetails") }
        #if DEBUG
        return true
        #else
        return false
        #endif
    }

    /// The message for an error, with the error itself below it when
    /// details is set. The error is logged either way.
    nonisolated static func describe(_ error: Error, details: Bool = showsErrorDetails) -> String {
        let (text, detail) = summary(error)
        log.error("\(text, privacy: .public) \(detail, privacy: .public)")
        return details ? text + "\n\n" + detail : text
    }

    nonisolated static func summary(_ error: Error) -> (String, String) {
        switch error {
        case Control.Failure.notRunning(let why):
            return (String(localized: "The CBB service is not running on this Mac. Install it, or start it with sudo launchctl kickstart system/tools.cbb."), why)
        case Control.Failure.denied:
            return (String(localized: "No permission to use the service: add your user to the _cbb group and log in again."), "EACCES")
        case Control.Failure.refused(let text, let detail):
            return (text, detail ?? String(reflecting: error))
        case Admin.Failure.noCommand:
            return (String(localized: "cbb is not installed in /usr/local/bin or /opt/homebrew/bin."), String(reflecting: error))
        case Admin.Failure.failed(let text, let detail):
            return (text, detail)
        case is Arrangement.Refused:
            return (String(localized: "The tiles stay as they were: that change does not fit."), String(reflecting: error))
        default:
            return (String(localized: "The service answered something unexpected."), String(reflecting: error))
        }
    }
}
