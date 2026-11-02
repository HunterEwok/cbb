// SPDX-License-Identifier: AGPL-3.0-only

import AppKit
import os
import SwiftUI

private let log = Logger(subsystem: "io.github.hunterewok.clipboardbridge.mac", category: "app")

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

    /// The menu bar's symbol: linked while another device is online.
    var symbol: String {
        if problem != nil || !inGroup { return "clipboard" }
        return others.contains { $0.online } ? "link.circle.fill" : "link.circle"
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

    /// The devices and collections below this Mac, in the user's order: the
    /// group's order until the user changes it.
    var arranged: [Arranged] {
        let others = self.others
        guard let a = arrangement else { return others.map { .device($0) } }
        let byID = Dictionary(others.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
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

    func remove(_ id: String) async { await admin(["revoke", id], done: String(localized: "Removed from the group.")) }
    /// The dialog that asks first warns that the computer's key is a file,
    /// which -allow-file-key consents to.
    func makeAdmin(_ id: String) async { await admin(["admin", "-allow-file-key", id], done: String(localized: "It is an admin now.")) }
    func freeze(_ id: String) async { await admin(["freeze", id], done: String(localized: "Frozen.")) }
    /// On the group's root: voids both histories of every key that signed two.
    func resolve() async {
        await admin(["resolve"], done: String(localized: "Both histories are void. The device signs its records again by itself."))
    }
    func unfreeze(_ id: String) async { await admin(["unfreeze", id], done: String(localized: "Unfrozen.")) }

    /// Sets the sync mode: this Mac's with id nil, or on an admin another
    /// device's, which cbb sends it as a signed command.
    func setMode(_ mode: SyncMode, on id: String? = nil) async {
        let arguments = id.map { ["mode", "-on", $0, mode.rawValue] } ?? ["mode", mode.rawValue]
        await admin(arguments, done: String(localized: "The sync mode is set."))
    }

    /// Turns sync away from home on or off; on needs the user's yes to the
    /// warning the app showed, which cbb asks for.
    func setAway(_ on: Bool) async {
        await admin(["global", on ? "on" : "off"], answer: on, done: on ? String(localized: "Sync away from home is on.") : String(localized: "Sync away from home is off."))
    }

    private func admin(_ arguments: [String], answer: Bool = false, done: String) async {
        let details = Self.showsErrorDetails
        await act {
            _ = try await Admin.run(arguments, answer: answer, details: details)
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
    /// defaults write io.github.hunterewok.clipboardbridge.mac ShowErrorDetails -bool YES).
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
            return (String(localized: "The Clipboard Bridge service is not running on this Mac. Install it, or start it with sudo launchctl kickstart system/io.github.hunterewok.clipboardbridge."), why)
        case Control.Failure.denied:
            return (String(localized: "No permission to use the service: add your user to the _clipboardbridge group and log in again."), "EACCES")
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
