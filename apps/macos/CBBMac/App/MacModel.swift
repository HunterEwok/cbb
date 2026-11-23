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
    @Published private(set) var devices: [Control.Device] = []
    /// The devices and collections, this Mac among them, in the user's
    /// order as the service keeps it (docs/apps.md, "What the member
    /// shows"), and whether the user changed it.
    @Published private(set) var arranged: [Arranged] = []
    @Published private(set) var customOrder = false
    /// Why the service cannot be reached; nil while it answers.
    @Published private(set) var problem: String?
    /// The outcome of the last action, for a line under it.
    @Published var message: String?
    /// The mutes asked for and not yet answered, by device (this Mac's
    /// own sync by its id too): the tile shows the new state at once and
    /// goes back only when the change is refused.
    @Published private(set) var pendingMute: [String: Bool] = [:]
    @Published private(set) var busy = false
    /// Whether a pairing window is open (AddDeviceSheet), and its digits
    /// and QR code once cbb wrote them.
    @Published private(set) var pairing = false
    @Published private(set) var window: PairingWindow?
    /// The window asks before Everywhere turns on (D-82); the menu bar's
    /// item sets it and opens the window.
    @Published var askingAway = false
    /// Settings, a sheet on the window, which the menu bar item opens too.
    @Published var settingsShown = false
    private var windowFile: URL?
    private var windowCancelled = false
    /// The bug report the window asks about (BugSheet), in release mode.
    @Published private(set) var bug: BugOffer?
    private var askingBug = false
    /// Whether a remote invitation is open (InviteSheet), and its state
    /// once cbb wrote it.
    @Published private(set) var inviting = false
    @Published private(set) var invitation: Invitation?
    private var inviteFiles: (state: URL, answers: URL)?
    private var inviteCancelled = false
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
            var view = Control.View()
            if let st = answer.status, st.group?.isEmpty == false, st.removed != true {
                view = try await client.request(.init(op: "view")).0.view ?? Control.View()
            }
            show(status: answer.status, view: view)
            problem = nil
            if answer.status?.bug == true, bug == nil, !askingBug { await askBug() }
        } catch {
            problem = Self.describe(error)
        }
    }

    /// The service's bug report as the window shows it: the report as
    /// "Technical details" shows it, whether to offer "Always allow", and
    /// the version that fixes this break.
    struct BugOffer: Identifiable, Equatable {
        var report: String
        var offerAlways: Bool
        var fixedIn: String
        var id: String { report }
    }

    /// Reads the bug report of the service's panic before its last start
    /// (docs/core-api.md, "Bug reports"): in debug mode the message shows
    /// what broke and nothing is asked; in release mode the window asks,
    /// unless the core says to send or skip it.
    func askBug() async {
        askingBug = true
        defer { askingBug = false }
        guard let answer = try? await client.request(.init(op: "bug")), !answer.1.isEmpty,
              let offer = Self.bugOffer(answer.1) else { return }
        log.error("the service broke and started again: \(offer.details, privacy: .public)")
        if Self.showsErrorDetails || offer.action != "ask" {
            if Self.showsErrorDetails {
                message = String(localized: "Something in CBB broke. It started again.") + "\n\n" + offer.details
            }
            await cancelBug()
            return
        }
        bug = BugOffer(report: offer.report, offerAlways: offer.offerAlways, fixedIn: offer.fixedIn)
    }

    /// What the service's bug answer holds: what the app does, the report
    /// as readable text, its details, "Always allow" and fixed_in.
    nonisolated static func bugOffer(_ data: Data) -> (action: String, report: String, details: String, offerAlways: Bool, fixedIn: String)? {
        guard let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let report = o["report"] as? [String: Any] else { return nil }
        let text = (try? JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]))
            .map { String(decoding: $0, as: UTF8.self) } ?? ""
        return (o["action"] as? String ?? "", text, report["details"] as? String ?? "", o["offer_always"] as? Bool ?? false, o["fixed_in"] as? String ?? "")
    }

    /// The user allowed the report, and maybe always: the service sends it.
    func allowBug(always: Bool) async {
        bug = nil
        let payload = (try? JSONSerialization.data(withJSONObject: ["always": always])) ?? Data()
        do {
            _ = try await client.request(.init(op: "bug_allow"), payload: payload)
        } catch {
            message = Self.describe(error)
        }
    }

    /// The user did not allow the report: the service forgets it.
    func cancelBug() async {
        bug = nil
        do {
            _ = try await client.request(.init(op: "bug_cancel"))
        } catch {
            message = Self.describe(error)
        }
    }

    /// Shows what the service said: its status, then the group's tiles.
    func show(status: Control.Status?, view: Control.View) {
        self.status = status
        show(view: view)
    }

    /// Shows the member's tiles, and the devices in them.
    func show(view: Control.View) {
        var all: [Control.Device] = []
        arranged = (view.tiles ?? []).compactMap { t in
            if let d = t.device {
                all.append(d)
                return .device(d)
            }
            guard let c = t.collection else { return nil }
            let ds = c.devices ?? []
            all += ds
            return .collection(Arrangement.Collection(id: c.id, name: c.name, devices: ds.map(\.id)), ds)
        }
        devices = all
        customOrder = view.custom ?? false
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

    /// Sends a change of the tiles to the service, which keeps it; one
    /// that does not fit leaves them as they were and says so.
    func arrange(_ op: Arrangement.Op) {
        guard let change = try? JSONDecoder().decode(Control.Change.self, from: op.data) else { return }
        var h = Control.Header(op: "arrange")
        h.arrange = change
        Task {
            do {
                let view = try await client.request(h).0.view ?? Control.View()
                show(view: view)
            } catch {
                let (_, detail) = Self.summary(error)
                log.error("arrange: \(detail, privacy: .public)")
                let text = String(localized: "The tiles stay as they were: that change does not fit.")
                message = Self.showsErrorDetails ? text + "\n\n" + detail : text
            }
        }
    }

    /// Asks macOS to let the app press keys for remote paste.
    func allowPaste() {
        Injector.askLeave()
        pasteAllowed = Injector.allowed
    }

    /// Makes a new group with this Mac as its root, as cbb new does as the
    /// administrator.
    func createGroup() async {
        await admin(["new"], done: String(localized: "The group is made: this Mac is its main device. Add a device with the + button."))
    }

    /// Installs the newest signed release the group passed around, as cbb
    /// update does as the administrator.
    func update() async { await admin(["update"], done: String(localized: "CBB is updated.")) }

    /// Moves the group to this Mac with its recovery key, typed from the
    /// sheet or its QR code's text, on cbb recovery's standard input; this
    /// Mac is the group's main device at once. The devices in leave (their
    /// IDs) leave the group in the same act; with card, secret is the PIN
    /// of the YubiKey that holds the key.
    func recover(_ secret: String, leave: [String] = [], card: Bool = false) async {
        let secret = secret.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !secret.isEmpty else { return }
        var arguments = ["recovery"]
        for id in leave { arguments += ["-leave", id] }
        if card { arguments.append("-yubikey") }
        await admin(arguments, input: secret + "\n", done: String(localized: "This Mac is the group's main device now."))
    }

    /// Sets how long a copy and a secret live in the group (cbb ttl,
    /// D-129), in milliseconds; nil keeps one as it is.
    func setTTL(copyMS: Int64?, secretMS: Int64?) async {
        func value(_ ms: Int64?) -> String { ms.map { "\($0 / 1000)s" } ?? "-" }
        await admin(["ttl", value(copyMS), value(secretMS)], done: String(localized: "Saved. Every device of the group follows it."))
    }

    /// Sets which keys may be the group's admins and hubs (cbb keys), on the
    /// main device: proven, hardware or files.
    func setKeyLevel(_ level: String) async {
        await admin(["keys", level], done: String(localized: "Saved. Every device of the group follows it."))
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
    /// Takes the networks this Mac is on now as ones where the group is, as
    /// cbb network does with administrator privileges.
    func homeNetwork() async {
        await admin(["network"], done: String(localized: "This network counts as home now."))
    }
    /// Whether the group has a hub other than d that this Mac knows of.
    func otherHub(than d: Control.Device) -> Bool {
        devices.contains { $0.id != d.id && $0.hub }
    }
    /// How a hub's tunnel hides: plain WireGuard, AmneziaWG or VLESS over
    /// it, which the two switches of strict networks set.
    enum HubTunnel: String, CaseIterable, Identifiable {
        case plain, obfuscate, vless
        var id: String { rawValue }
    }

    /// How this Mac's tunnel hides while it is a hub.
    var hubTunnel: HubTunnel {
        guard let a = status?.away else { return .plain }
        return a.vless == true ? .vless : a.obfuscated == true ? .obfuscate : .plain
    }

    /// Sets how this hub's tunnel hides (VLESS, which a hub with a
    /// forwarder offers by default, AmneziaWG alone or plain WireGuard) and,
    /// with forwarder, its forwarder ("default" for the project's), keeping
    /// its addresses and port.
    func setHub(_ tunnel: HubTunnel, forwarder: String? = nil, key: String? = nil) async {
        var args = ["global", "hub", "-keep", "-firewall", "no"]
        switch tunnel {
        case .plain: args += ["-no-obfuscate", "-no-vless"]
        case .obfuscate: args.append("-no-vless")
        case .vless: break
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
    func setSync(_ on: Bool, on id: String? = nil) async {
        guard let id else { return await turnSync(on) }
        await admin(["sync", "-on", id, on ? "on" : "off"], done: String(localized: "Sync is set."))
    }

    /// Turns sync away from home on or off; on needs the user's yes to the
    /// warning the app showed, which cbb asks for.
    func setAway(_ on: Bool) async {
        await admin(["global", on ? "on" : "off"], answer: on, done: on ? String(localized: "Sync away from home is on.") : String(localized: "Sync away from home is off."))
    }

    /// Whether sync is off on this Mac now, and until when, nil for until
    /// it is turned on again.
    var syncOff: Bool { status?.mode == "own" }
    var syncOffUntil: Date? { Self.date(ms: status?.syncUntilMS) }
    /// Whether an admin muted this Mac, and until when.
    var muted: Bool { status?.muted == true }
    var mutedUntil: Date? { Self.date(ms: status?.mutedUntilMS) }

    /// Whether a device's tile shows it muted: the answer still awaited,
    /// else its mute; for this Mac, its sync turned off.
    func shownMuted(_ d: Control.Device) -> Bool {
        if let p = pendingMute[d.id] { return p }
        return d.isSelf ? syncOff : d.muted
    }

    /// Whether this Mac may mute the device from its tile: its own sync
    /// always, another device only as an admin.
    func mayMute(_ d: Control.Device) -> Bool { d.isSelf || isAdmin }

    /// Turns this Mac's sync off, or on, from its tile, showing the new
    /// state while the service answers.
    func turnSyncFromTile(_ id: String, on: Bool, forMS: Int64 = 0) async {
        pendingMute[id] = !on
        defer { pendingMute[id] = nil }
        await turnSync(on, forMS: forMS)
    }

    nonisolated static func date(ms: Int64?) -> Date? {
        guard let ms, ms > 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
    }

    /// Turns this Mac's sync on, or off for forMS milliseconds, 0 for until
    /// turned on again: the clipboard is then this Mac's own. Any user of
    /// the Mac may, over the plain socket.
    func turnSync(_ on: Bool, forMS: Int64 = 0) async {
        var h = Control.Header(op: "sync")
        h.on = on
        if !on, forMS > 0 { h.forMS = forMS }
        await act {
            _ = try await self.client.request(h)
            return on ? String(localized: "Sync is on here: copies go to the group and come from it.") : String(localized: "Sync is off here: the clipboard is this Mac's own.")
        }
    }

    /// On an admin: mutes a device for the whole group, for forMS
    /// milliseconds, 0 for until an admin unmutes it; its copies then stay
    /// its own.
    /// This Mac itself goes over the plain socket, which the service takes
    /// for muting or unmuting its own device, so no password is asked.
    func mute(_ id: String, forMS: Int64 = 0) async {
        pendingMute[id] = true
        defer { pendingMute[id] = nil }
        let done = String(localized: "Muted: its copies do not reach the group.")
        if let h = Self.ownMute(id, on: true, forMS: forMS, me: status?.device) {
            return await plain(h, done: done)
        }
        var arguments = ["mute", "-on", id]
        if forMS > 0 { arguments += ["-for", "\(forMS)ms"] }
        await admin(arguments, done: done)
    }

    func unmute(_ id: String) async {
        pendingMute[id] = false
        defer { pendingMute[id] = nil }
        let done = String(localized: "Unmuted: its copies reach the group again.")
        if let h = Self.ownMute(id, on: false, me: status?.device) {
            return await plain(h, done: done)
        }
        await admin(["unmute", "-on", id], done: done)
    }

    /// The request that mutes or unmutes this Mac itself on the plain
    /// socket; nil for another device, which takes the administrator.
    nonisolated static func ownMute(_ id: String, on: Bool, forMS: Int64 = 0, me: String?) -> Control.Header? {
        guard let me, !me.isEmpty, id == me else { return nil }
        var h = Control.Header(op: on ? "mute" : "unmute")
        h.device = id
        if on, forMS > 0 { h.forMS = forMS }
        return h
    }

    private func plain(_ h: Control.Header, done: String) async {
        await act {
            _ = try await self.client.request(h)
            return done
        }
    }

    /// What cbb pair -app writes in a group (member/src/admit_cli.rs): the
    /// window's six digits, its QR code's text, its address and how long it
    /// stays open, the last device that failed and the one that joined;
    /// with when it closes.
    struct PairingWindow: Decodable, Equatable {
        let code: String
        let qr: String
        let address: String?
        let expires: Int
        let refused: String?
        let done: Bool?
        let name: String?
        var ends = Date()

        private enum CodingKeys: String, CodingKey { case code, qr, address, expires, refused, done, name }

        /// The six digits as "123 456"; nil when cbb wrote no such code.
        var digits: String? {
            guard code.count == 6, code.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
            return String(code.prefix(3)) + " " + String(code.suffix(3))
        }
    }

    /// Opens a pairing window for a new device on the root or an admin: cbb
    /// pair -app runs as the administrator and writes the window's six
    /// digits, which a new computer types, and its QR code, which a new
    /// phone scans (D-119), into a file the app made; closeWindow removes
    /// the file, and cbb closes the window. With asAdmin, on the group's
    /// root, the phone that joins becomes an admin. Returns when the window
    /// closes.
    func openWindow(asAdmin: Bool = false) async {
        guard !pairing else { return }
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-window-\(UUID().uuidString).json")
        guard FileManager.default.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            message = Self.describe(Admin.Failure.failed(String(localized: "The app could not make the file for the QR code."), detail: file.path))
            return
        }
        pairing = true
        windowFile = file
        windowCancelled = false
        let poll = Task { [weak self] in
            var ends: Date?
            while !Task.isCancelled {
                if let data = try? Data(contentsOf: file), var w = try? JSONDecoder().decode(PairingWindow.self, from: data) {
                    let end = ends ?? Date().addingTimeInterval(TimeInterval(w.expires))
                    ends = end
                    w.ends = end
                    if self?.window != w { self?.window = w }
                }
                try? await Task.sleep(for: .milliseconds(400))
            }
        }
        let details = Self.showsErrorDetails
        await act { [weak self] in
            do {
                _ = try await Admin.run(["pair", "-app", file.path] + (asAdmin ? ["-admin"] : []), details: details)
            } catch {
                if self?.windowCancelled == true { throw Admin.Failure.cancelled }
                throw error
            }
            return String(localized: "It joined the group.")
        }
        poll.cancel()
        try? FileManager.default.removeItem(at: file)
        windowFile = nil
        window = nil
        pairing = false
    }

    /// Closes the pairing window: cbb sees its file gone and hangs up.
    func closeWindow() {
        guard let file = windowFile else { return }
        windowCancelled = true
        try? FileManager.default.removeItem(at: file)
    }

    /// Joins a group by the six digits of a pairing window open on one of
    /// its devices: cbb pair -code as the administrator, with the digits on
    /// its standard input, never its command line (D-119).
    func joinGroup(_ text: String) async {
        guard let digits = Self.shownCode(text) else {
            message = String(localized: "Type the six digits the pairing window shows.")
            return
        }
        await admin(["pair", "-code"], input: digits + "\n", done: String(localized: "Joined the group."))
    }

    /// What cbb invite -app writes (member/src/admit_cli.rs): the
    /// invitation's text, how long it is valid, the device that asks to
    /// join, and the name of the one that joined; with when it ends.
    struct Invitation: Decodable, Equatable {
        struct Joining: Decodable, Equatable {
            let name: String
            let os: String
            let fingerprint: String
        }

        let invite: String
        let expires: Int
        let joining: Joining?
        let done: Bool?
        let name: String?
        var ends = Date()

        private enum CodingKeys: String, CodingKey { case invite, expires, joining, done, name }
    }

    /// Opens a remote invitation for a device far away (docs/protocol.md,
    /// section 12) on the group's hub: cbb invite -app runs as the
    /// administrator, writes the invitation's state into a file the app
    /// made, and reads the user's answer about the device that uses it from
    /// another; cancelInvite removes the first, and cbb hangs up.
    func invite() async {
        guard !inviting, !busy else { return }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-invite-\(UUID().uuidString)")
        let state = dir.appendingPathComponent("invite.json"), answers = dir.appendingPathComponent("answers")
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        } catch {
            message = Self.describe(error)
            return
        }
        defer { try? FileManager.default.removeItem(at: dir) }
        guard FileManager.default.createFile(atPath: state.path, contents: nil, attributes: [.posixPermissions: 0o600]),
              FileManager.default.createFile(atPath: answers.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            message = Self.describe(Admin.Failure.failed(String(localized: "The app could not make the file for the QR code."), detail: dir.path))
            return
        }
        inviting = true
        inviteFiles = (state, answers)
        inviteCancelled = false
        let poll = Task { [weak self] in
            var ends: Date?
            while !Task.isCancelled {
                if let data = try? Data(contentsOf: state), var inv = try? JSONDecoder().decode(Invitation.self, from: data) {
                    let end = ends ?? Date().addingTimeInterval(TimeInterval(inv.expires))
                    ends = end
                    inv.ends = end
                    if self?.invitation != inv { self?.invitation = inv }
                }
                try? await Task.sleep(for: .milliseconds(400))
            }
        }
        let details = Self.showsErrorDetails
        await act { [weak self] in
            do {
                _ = try await Admin.run(["invite", "-for", "1h", "-app", state.path, "-answers", answers.path], details: details)
            } catch {
                if self?.inviteCancelled == true { throw Admin.Failure.cancelled }
                throw error
            }
            return String(localized: "The device joined the group; it appears in the list once it connects.")
        }
        poll.cancel()
        inviteFiles = nil
        invitation = nil
        inviting = false
    }

    /// The user's answer about the device that used the invitation: yes
    /// admits it.
    func answerInvite(_ yes: Bool) {
        guard let answers = inviteFiles?.answers, let h = try? FileHandle(forWritingTo: answers) else { return }
        defer { try? h.close() }
        _ = try? h.seekToEnd()
        try? h.write(contentsOf: Data((yes ? "yes\n" : "no\n").utf8))
    }

    /// Ends the invitation: cbb sees its file gone and hangs up.
    func cancelInvite() {
        guard let state = inviteFiles?.state else { return }
        inviteCancelled = true
        try? FileManager.default.removeItem(at: state)
    }

    /// The six digits a pairing window shows, as typed: spaces and dashes
    /// between them are fine; nil when text is not such a code.
    nonisolated static func shownCode(_ text: String) -> String? {
        let kept = text.filter { $0 != " " && $0 != "-" }
        guard kept.count == 6, kept.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return kept
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
        default:
            return (String(localized: "The service answered something unexpected."), String(reflecting: error))
        }
    }
}
