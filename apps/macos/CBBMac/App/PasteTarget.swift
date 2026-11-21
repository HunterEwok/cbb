// SPDX-License-Identifier: AGPL-3.0-only

import AppKit
import Carbon.HIToolbox
import os

private let log = Logger(subsystem: "tools.cbb.mac", category: "paste")

/// Remote paste on this Mac (docs/design.md, "Remote paste"): only an app
/// may press keys, once its user allowed it in Accessibility, so the app,
/// not the service or its pasteboard agent, is the Mac's desktop target. It
/// keeps a watch connection that only pastes (docs/protocol.md, section 8)
/// and answers each inject.
final class PasteTarget {
    fileprivate let client: ControlClient
    private let queue = DispatchQueue(label: "tools.cbb.mac.paste")
    private var started = false

    init(client: ControlClient = ControlClient()) { self.client = client }

    /// Connects, and connects again whenever the service goes away.
    func start() {
        guard !started else { return }
        started = true
        queue.async { [self] in
            while true {
                do {
                    try serve()
                } catch {
                    log.info("remote paste: \(String(describing: error), privacy: .public)")
                }
                Thread.sleep(forTimeInterval: 5)
            }
        }
    }

    private func serve() throws {
        let fd = try client.connect(timeout: 0)
        defer { close(fd) }
        var watch = Control.Header(op: "watch")
        watch.inject = "desktop"
        watch.pasteOnly = true
        watch.images = true
        watch.files = true
        watch.html = true
        try ControlClient.send(fd, Control.encode(watch))
        var data = Data()
        guard let (answer, _) = try ControlClient.receive(fd, into: &data) else { return }
        if let error = answer.error { throw Control.Failure.refused(error, detail: answer.detail) }
        while let (m, payload) = try ControlClient.receive(fd, into: &data) {
            guard m.op == "inject", let seq = m.seq else { continue }
            var done = Control.Header(op: "injected")
            done.seq = seq
            let text = String(decoding: payload, as: UTF8.self)
            // A menu bar app in the background naps, which stretches its
            // waits; the paste is the user's own action and must answer soon.
            let activity = ProcessInfo.processInfo.beginActivity(options: .userInitiated, reason: "remote paste")
            defer { ProcessInfo.processInfo.endActivity(activity) }
            let failure = m.kind == "media"
                ? pasteCopy(text, enter: m.enter == true)
                : Injector.inject(text, method: m.method ?? "paste", enter: m.enter == true, secret: m.kind == "secret")
            if let failure {
                done.error = failure.reason
                done.refused = failure.refused ? true : nil
                log.notice("remote paste from \(m.name ?? "?", privacy: .public): \(failure.reason, privacy: .public)")
            } else {
                log.notice("remote paste from \(m.name ?? "?", privacy: .public): \(payload.count) bytes")
            }
            try ControlClient.send(fd, Control.encode(done))
        }
    }
}

extension PasteTarget {
    /// Pastes the group's copy of images or files that a remote paste
    /// names (docs/protocol.md, section 15): fetches it from the service
    /// with paste-media, writes it into the pasteboard, then Cmd+V.
    func pasteCopy(_ id: String, enter: Bool) -> Injector.Failure? {
        if let why = Injector.blocked() { return why }
        let copy: FetchedCopy
        do {
            copy = try fetch(id)
        } catch {
            return Injector.Failure(reason: "fetching the copy: \(error)", refused: false)
        }
        return Injector.pasteCopy(copy, enter: enter)
    }

    /// The copy id from the service: its text, and its parts with their
    /// bytes; files are saved in a new folder of their own.
    private func fetch(_ id: String) throws -> FetchedCopy {
        let fd = try client.connect(timeout: 30)
        defer { close(fd) }
        var req = Control.Header(op: "paste_media")
        req.value = id
        try ControlClient.send(fd, Control.encode(req))
        var data = Data()
        guard let (first, text) = try ControlClient.receive(fd, into: &data) else { throw Control.Failure.broken("the service closed the connection") }
        if let error = first.error { throw Control.Failure.refused(error, detail: first.detail) }
        var copy = FetchedCopy(text: String(decoding: text, as: UTF8.self))
        var folder: URL?
        var current: FileHandle?
        defer { try? current?.close() }
        while let (m, payload) = try ControlClient.receive(fd, into: &data) {
            if let error = m.error { throw Control.Failure.refused(error, detail: m.detail) }
            if m.done == true { break }
            if let p = m.part {
                try? current?.close()
                current = nil
                if let path = p.path {
                    let root = try folder ?? FetchedCopy.newFolder()
                    folder = root
                    let url = try FetchedCopy.place(path, in: root)
                    if p.dir == true {
                        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
                    } else {
                        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                        guard FileManager.default.createFile(atPath: url.path, contents: nil) else { throw Control.Failure.broken("cannot write \(path)") }
                        // From another device: Gatekeeper checks it before
                        // it first opens, wherever it is pasted.
                        try FetchedCopy.markDownloaded(url)
                        current = try FileHandle(forWritingTo: url)
                    }
                    if !path.contains("/") { copy.files.append(url) }
                } else if let type = p.type {
                    copy.data.append((type, Data()))
                }
                continue
            }
            if let h = current {
                try h.write(contentsOf: payload)
            } else if !copy.data.isEmpty {
                copy.data[copy.data.count - 1].1.append(payload)
            }
        }
        return copy
    }
}

/// A copy of images or files fetched for a remote paste.
struct FetchedCopy {
    var text: String
    var data: [(String, Data)] = []
    var files: [URL] = []

    /// The quarantine attribute of a file received at `time`, as cbb's and
    /// Go's mark: the flags, the time in hexadecimal, the agent.
    static func quarantine(at time: Date) -> String {
        String(format: "0083;%llx;CBB;", UInt64(max(0, time.timeIntervalSince1970)))
    }

    /// Marks a file from another device as downloaded, so that Gatekeeper
    /// checks it before it first opens; a volume without extended
    /// attributes keeps it unmarked.
    static func markDownloaded(_ url: URL, at time: Date = Date()) throws {
        let value = quarantine(at: time)
        let r = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return value.withCString { setxattr(path, "com.apple.quarantine", $0, strlen($0), 0, 0) }
        }
        if r != 0 && errno != ENOTSUP {
            throw Control.Failure.broken("cannot mark \(url.lastPathComponent) as downloaded: errno \(errno)")
        }
    }

    /// How long the files of a paste stay for the app that pasted them.
    static let keepFor: TimeInterval = 600

    /// A new folder for the files of a pasted copy, in the app's caches.
    static func newFolder() throws -> URL {
        let base = try FileManager.default.url(for: .cachesDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let pasted = base.appendingPathComponent("Pasted", isDirectory: true)
        // The files of earlier pastes go after a while, as the desktop
        // connector's folders of copies do.
        let old = (try? FileManager.default.contentsOfDirectory(at: pasted, includingPropertiesForKeys: [.contentModificationDateKey])) ?? []
        for dir in old {
            let date = (try? dir.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? .distantPast
            if date.timeIntervalSinceNow < -keepFor { try? FileManager.default.removeItem(at: dir) }
        }
        let url = pasted.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// Where the copy's path goes under root: the service checked its
    /// names (docs/protocol.md, section 4, "Media"), and none leaves root.
    static func place(_ path: String, in root: URL) throws -> URL {
        let names = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !names.isEmpty, names.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw Control.Failure.broken("the copy has a path that is not valid")
        }
        return names.reduce(root) { $0.appendingPathComponent(String($1)) }
    }
}

extension Injector {
    /// Writes a fetched copy into the pasteboard, then presses Cmd+V, and
    /// Return when enter is set. The pasteboard keeps it, as the group's
    /// copy it is; the transient marker keeps the agent from sending it
    /// back as a new copy.
    static func pasteCopy(_ copy: FetchedCopy, enter: Bool) -> Failure? {
        let written = onMainThread { () -> Bool in
            let pb = NSPasteboard.general
            pb.clearContents()
            if !copy.files.isEmpty {
                guard pb.writeObjects(copy.files as [NSURL]) else { return false }
                pb.pasteboardItems?.first?.setData(Data(), forType: transient)
                return true
            }
            let item = NSPasteboardItem()
            for (type, data) in copy.data {
                switch type {
                case "image/png": item.setData(data, forType: .png)
                case "image/jpeg":
                    // Few apps read JPEG from the pasteboard; TIFF they all do.
                    if let tiff = NSImage(data: data)?.tiffRepresentation { item.setData(tiff, forType: .tiff) }
                    item.setData(data, forType: NSPasteboard.PasteboardType("public.jpeg"))
                case "image/gif":
                    // An animation where apps take GIF, its first frame elsewhere.
                    item.setData(data, forType: NSPasteboard.PasteboardType("com.compuserve.gif"))
                    if let tiff = NSImage(data: data)?.tiffRepresentation { item.setData(tiff, forType: .tiff) }
                case "text/html": item.setData(data, forType: .html)
                default: continue
                }
            }
            if !copy.text.isEmpty { item.setString(copy.text, forType: .string) }
            item.setData(Data(), forType: transient)
            return pb.writeObjects([item])
        }
        guard written else { return Failure(reason: "the pasteboard took no copy", refused: false) }
        var strokes = [Stroke.paste]
        if enter { strokes.append(.key(CGKeyCode(kVK_Return))) }
        return press(strokes)
    }

    fileprivate static func onMainThread<T>(_ work: () -> T) -> T {
        Thread.isMainThread ? work() : DispatchQueue.main.sync(execute: work)
    }
}

/// Puts a text where the keyboard focus is: through the pasteboard and
/// Cmd+V, or typed as Unicode key events, which no keyboard layout changes.
enum Injector {
    struct Failure: Error, Equatable {
        var reason: String
        var refused = true
    }

    /// How long the app with the focus has to read a pasted text before the
    /// pasteboard gets its items back (internal/connector.RestoreAfter).
    static let restoreAfter: TimeInterval = 0.5
    /// A key event carries at most this many UTF-16 units.
    static let unitsPerEvent = 20

    /// The marker of nspasteboard.org that tells clipboard histories, and
    /// the pasteboard agent, to skip an item: what the paste puts in the
    /// pasteboard is not a copy for the group.
    static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
    static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    /// The type Universal Clipboard marks another Apple device's items with.
    static let remoteClipboard = NSPasteboard.PasteboardType("com.apple.is-remote-clipboard")

    /// Whether macOS lets the app press keys (Accessibility). The answer of
    /// CGPreflightPostEventAccess can stay what it was when the app started,
    /// so a leave given in System Settings while the app runs shows through
    /// AXIsProcessTrusted, which reads the setting each time.
    static var allowed: Bool { AXIsProcessTrusted() || CGPreflightPostEventAccess() }

    /// Asks macOS for leave to press keys. macOS asks only once; after that,
    /// and when the user took the leave back by hand, the app opens the
    /// Accessibility pane of System Settings itself.
    static func askLeave() {
        if CGRequestPostEventAccess() { return }
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
            NSWorkspace.shared.open(url)
        }
    }

    /// Why keys cannot go to the focus now, or nil.
    static func blocked() -> Failure? {
        if !allowed {
            return Failure(reason: "CBB may not press keys on this Mac; its user allows it in System Settings, Privacy & Security, Accessibility")
        }
        let session = CGSessionCopyCurrentDictionary() as? [String: Any] ?? [:]
        if session["kCGSSessionOnConsoleKey"] as? Bool == false {
            return Failure(reason: "this user's session is not the one on the screen")
        }
        if session["CGSSessionScreenIsLocked"] as? Bool == true {
            return Failure(reason: "the screen is locked")
        }
        if IsSecureEventInputEnabled() {
            return Failure(reason: "a password field or Secure Keyboard Entry has the keyboard, and macOS keeps keys from other apps out of it")
        }
        return nil
    }

    /// Puts text in; nil when it did.
    static func inject(_ text: String, method: String, enter: Bool, secret: Bool) -> Failure? {
        guard method == "paste" || method == "type" else { return Failure(reason: "this Mac pastes or types, not \(method)") }
        if let why = blocked() { return why }
        var strokes = method == "paste" ? [Stroke.paste] : strokes(for: text)
        if enter { strokes.append(.key(CGKeyCode(kVK_Return))) }
        if method == "paste" {
            return paste(text, secret: secret) { press(strokes) }
        }
        return press(strokes)
    }

    /// One key event: a key, Cmd+V, or up to unitsPerEvent UTF-16 units.
    enum Stroke: Equatable {
        case key(CGKeyCode)
        case paste
        case text([UniChar])
    }

    /// The strokes that type text: Return for a line break, Tab for a tab,
    /// the rest as Unicode in events of at most unitsPerEvent units, never
    /// splitting a surrogate pair.
    static func strokes(for text: String) -> [Stroke] {
        var out: [Stroke] = []
        var units: [UniChar] = []
        func flush() {
            if !units.isEmpty { out.append(.text(units)) }
            units = []
        }
        for ch in text.unicodeScalars {
            switch ch {
            case "\n":
                flush()
                out.append(.key(CGKeyCode(kVK_Return)))
            case "\t":
                flush()
                out.append(.key(CGKeyCode(kVK_Tab)))
            default:
                let u = Array(String(ch).utf16)
                if units.count + u.count > unitsPerEvent { flush() }
                units += u
            }
        }
        flush()
        return out
    }

    fileprivate static func press(_ strokes: [Stroke]) -> Failure? {
        let source = CGEventSource(stateID: .hidSystemState)
        for s in strokes {
            var key = CGKeyCode(0)
            var flags: CGEventFlags = []
            var units: [UniChar] = []
            switch s {
            case .key(let k): key = k
            case .paste: key = CGKeyCode(kVK_ANSI_V); flags = .maskCommand
            case .text(let u): units = u
            }
            for down in [true, false] {
                guard let e = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: down) else {
                    return Failure(reason: "macOS made no key event", refused: false)
                }
                e.flags = flags
                if !units.isEmpty { e.keyboardSetUnicodeString(stringLength: units.count, unicodeString: units) }
                e.post(tap: .cghidEventTap)
            }
            Thread.sleep(forTimeInterval: 0.003)
        }
        return nil
    }

    /// Puts text in the pasteboard, lets press paste it, and gives the
    /// pasteboard its items back after restoreAfter, unless the user copied
    /// meanwhile. Both writes carry the transient marker, so the agent
    /// syncs neither; a secret also carries the concealed one.
    private static func paste(_ text: String, secret: Bool, press: () -> Failure?) -> Failure? {
        let pb = NSPasteboard.general
        let (saved, ours) = onMain { () -> ([[(NSPasteboard.PasteboardType, Data)]], Int) in
            // What Universal Clipboard put here from another Apple device
            // comes from that device when it is read, which can take
            // seconds; the paste would miss its answer, so it is not kept.
            let remote = pb.types?.contains(remoteClipboard) == true
            let saved = remote ? [] : (pb.pasteboardItems ?? []).map { item in
                item.types.compactMap { t in item.data(forType: t).map { (t, $0) } }
            }
            pb.clearContents()
            let item = NSPasteboardItem()
            item.setString(text, forType: .string)
            item.setData(Data(), forType: transient)
            if secret { item.setData(Data(), forType: concealed) }
            pb.writeObjects([item])
            return (saved, pb.changeCount)
        }
        let failure = press()
        Thread.sleep(forTimeInterval: restoreAfter)
        onMain {
            guard pb.changeCount == ours else { return } // the user copied meanwhile
            pb.clearContents()
            let items = saved.map { pairs -> NSPasteboardItem in
                let item = NSPasteboardItem()
                for (t, d) in pairs { item.setData(d, forType: t) }
                return item
            }
            if let first = items.first {
                first.setData(Data(), forType: transient)
                pb.writeObjects(items)
            }
        }
        return failure
    }

    private static func onMain<T>(_ work: () -> T) -> T {
        Thread.isMainThread ? work() : DispatchQueue.main.sync(execute: work)
    }
}
