// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import Network
import os
import SwiftUI
import UIKit
import UniformTypeIdentifiers

private let log = Logger(subsystem: "tools.cbb", category: "share")

/// Share and the text selection menu's Share: sends the text, the link, an
/// image or files to the group's computers at home, as the app's Home
/// button sends the clipboard (docs/apps.md, "Share"). It dials the
/// computers it finds with the phone's own member key and closes once they
/// have it: for an image or files, once they fetched them from the phone.
final class ShareViewController: UIViewController {
    private let model = ShareModel()

    override func viewDidLoad() {
        super.viewDidLoad()
        let host = UIHostingController(rootView: ShareView(model: model) { [weak self] in
            self?.extensionContext?.completeRequest(returningItems: nil)
        })
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        let items = extensionContext?.inputItems as? [NSExtensionItem] ?? []
        Task { @MainActor in
            await model.send(items)
            if case .sent = model.state {
                try? await Task.sleep(for: .seconds(1))
                extensionContext?.completeRequest(returningItems: nil)
            }
        }
    }
}

@MainActor
final class ShareModel: ObservableObject {
    enum State: Equatable { case sending, sent, failed(String) }
    @Published var state = State.sending

    func send(_ items: [NSExtensionItem]) async {
        let what: OneShot.What
        do {
            if let media = try await Self.media(of: items) {
                what = media
            } else if let text = await Self.text(of: items), !text.isEmpty {
                what = .text(text)
            } else {
                state = .failed(String(localized: "There is no text to send."))
                return
            }
        } catch {
            state = .failed(String(localized: "What you shared is larger than 50 MB, more than Share can carry. Send less at a time."))
            return
        }
        do {
            try await OneShot.send(what)
            state = .sent
        } catch {
            let summary: String
            switch error {
            case OneShot.Failure.noGroup: summary = String(localized: "This phone is in no group yet: open CBB to make one or join one.")
            case OneShot.Failure.noKey: summary = String(localized: "Open CBB once, then share again.")
            case OneShot.Failure.noComputers: summary = String(localized: "No computer of your group answered. Are they on, and is this phone on the home network?")
            case OneShot.Failure.notFetched: summary = String(localized: "The computers did not fetch it within a minute. Try again, or send fewer files.")
            default: summary = String(localized: "Sending failed.")
            }
            let detail = String(reflecting: error)
            log.error("\(summary, privacy: .public) \(detail, privacy: .public)")
            state = .failed(Shared.showsErrorDetails ? summary + "\n\n" + detail : summary)
        }
    }

    /// The most an image or files may take together here: the extension
    /// holds them in its memory, which iOS keeps small.
    nonisolated static let maxShared = 50 << 20

    struct TooLarge: Error {}

    /// The shared image or files, nil when only a text or a link is shared.
    /// A single image goes as an image, so a computer can paste it.
    static func media(of items: [NSExtensionItem]) async throws -> OneShot.What? {
        let providers = items.flatMap { $0.attachments ?? [] }
        let isText = { (p: NSItemProvider) in
            p.hasItemConformingToTypeIdentifier(UTType.url.identifier) && !p.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier)
                || p.hasItemConformingToTypeIdentifier(UTType.plainText.identifier)
        }
        let media = providers.filter { !isText($0) && ($0.hasItemConformingToTypeIdentifier(UTType.image.identifier) || $0.hasItemConformingToTypeIdentifier(UTType.data.identifier)) }
        guard !media.isEmpty else { return nil }
        if media.count == 1, media[0].hasItemConformingToTypeIdentifier(UTType.image.identifier) {
            guard let image = await Images.load(media[0]), image.data.count <= maxShared else { throw TooLarge() }
            return .media([.data(image.data, type: image.type)])
        }
        var files: [(name: String, bytes: Data)] = []
        var total = 0
        for p in media {
            guard let (name, data) = await file(p) else { continue }
            total += data.count
            if total > maxShared { throw TooLarge() }
            files.append((name, data))
        }
        guard !files.isEmpty else { return nil }
        // Each name made one every system takes, and unique (Content.files).
        let names = Content.files(store: MemoryContent(maxBytes: 0), files: files.map { ($0.name, Data()) }).parts.compactMap(\.path)
        return .media(zip(names, files).map { CoreMember.Part.bytes($1.bytes, path: $0) })
    }

    /// The name and bytes of a shared file.
    static func file(_ p: NSItemProvider) async -> (String, Data)? {
        let type = p.registeredContentTypes.first { $0.conforms(to: .data) } ?? .data
        let suggested = p.suggestedName
        return await withCheckedContinuation { c in
            _ = p.loadFileRepresentation(for: type, openInPlace: false) { url, _, _ in
                guard let url, let d = try? Data(contentsOf: url) else { return c.resume(returning: nil) }
                // The suggested name may lack the file's extension.
                var name = suggested ?? url.lastPathComponent
                if !url.pathExtension.isEmpty, (name as NSString).pathExtension.isEmpty { name += "." + url.pathExtension }
                c.resume(returning: (name, d))
            }
        }
    }

    /// The shared text, or the shared link as text.
    static func text(of items: [NSExtensionItem]) async -> String? {
        for item in items {
            for p in item.attachments ?? [] {
                if p.hasItemConformingToTypeIdentifier(UTType.url.identifier),
                   let url = try? await p.loadItem(forTypeIdentifier: UTType.url.identifier) as? URL {
                    return url.absoluteString
                }
                if p.hasItemConformingToTypeIdentifier(UTType.plainText.identifier),
                   let s = try? await p.loadItem(forTypeIdentifier: UTType.plainText.identifier) as? String {
                    return s
                }
            }
            if let s = item.attributedContentText?.string, !s.isEmpty { return s }
        }
        return nil
    }
}

struct ShareView: View {
    @ObservedObject var model: ShareModel
    let done: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            switch model.state {
            case .sending:
                ProgressView()
                Text("Sending to your computers…")
            case .sent:
                Image(systemName: "checkmark.circle").font(.largeTitle)
                Text("Sent to your computers.")
            case .failed(let message):
                Image(systemName: "exclamationmark.triangle").font(.largeTitle)
                Text(verbatim: message).multilineTextAlignment(.center)
            }
            Button(action: done) { Text("Done") }
                .buttonStyle(.borderedProminent)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(uiColor: .systemBackground))
    }
}

/// One send: the phone's member in the core, in a folder of its own,
/// dials the computers of the group that browsing finds, as the app does,
/// and hands them the text, or the images or files, once one is connected.
@MainActor
enum OneShot {
    enum Failure: Error { case noGroup, noKey, noComputers, notFetched }

    /// What Share sends: a text, or images or files.
    enum What {
        case text(String)
        case media([CoreMember.Part])
    }

    /// Holds the browser for its own callback, which resolves the members
    /// it finds.
    private final class BrowserRef: @unchecked Sendable { var browser: BonjourBrowser? }

    static func send(_ what: What, wait: Duration = .seconds(8), fetchWait: Duration = .seconds(60)) async throws {
        guard let g = try PhoneGroup.load(from: Shared.groupFile) else { throw Failure.noGroup }
        guard let key = try KeychainIdentity.loadKey(label: Shared.memberLabel) else { throw Failure.noKey }
        let signer = try SecKeySigner(key)
        // A folder of its own: the app's member keeps the other, and may run.
        let dir = Shared.groupFile.deletingLastPathComponent().appendingPathComponent("share-member", isDirectory: true)
        try? FileManager.default.removeItem(at: dir)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let node = try CoreMember(.init(dir: dir, name: UIDevice.current.name, osVersion: UIDevice.current.systemVersion, device: g.device,
                                        publicKeyDER: signer.publicKeyDER, seal: try SealKey.secret(), cert: g.memberCert,
                                        issuer: g.memberIssuer, groupCA: g.groupCA, roots: g.trusted)) { try signer.signature(digest: $0) }
        defer { node.stop() }
        try node.addRecords(g.records.records)
        // The members browsing finds, and those at the addresses they had
        // when admitted, only the group's devices.
        // Never this phone itself, which as a hub announces itself.
        let devices = Set(g.devices.map(\.id)).subtracting([g.device]), known = g.addresses, tag = g.tag
        let ref = BrowserRef()
        let browser = BonjourBrowser { found in
            Task {
                let members = Discovery.withKnown(found, known: Set(known.keys), group: tag).filter { $0.group == tag && devices.contains($0.device) }
                for m in members {
                    let resolved = found.contains { $0.device == m.device } ? await ref.browser?.addresses(of: m.device) ?? [] : []
                    let addrs = resolved + JoinCode.ordered(known[m.device] ?? []).filter { !resolved.contains($0) && LiveShare.numeric($0) }
                    if !addrs.isEmpty { try? node.found(m.device, addrs: addrs, device: m.device) }
                }
            }
        }
        ref.browser = browser
        browser.start()
        defer { browser.stop() }
        for (d, addrs) in known where devices.contains(d) {
            let a = JoinCode.ordered(addrs).filter(LiveShare.numeric)
            if !a.isEmpty { try? node.found(d, addrs: a, device: d) }
        }
        let online = try await node.wait(timeout: wait)
        var fetched = true
        if online {
            switch what {
            case let .text(text):
                try node.copy(text, board: false)
                // The copy goes out on the connections; give them a moment.
                try? await Task.sleep(for: .seconds(1))
            case let .media(parts):
                let c = try node.copyMedia(parts)
                // The computers fetch the copy's sealed blob from this phone.
                let end = ContinuousClock.now + fetchWait
                func done() -> Bool { (try? node.served(c.id)).map { $0.size == 0 || $0.served >= $0.size } ?? true }
                while !done(), ContinuousClock.now < end { try? await Task.sleep(for: .milliseconds(200)) }
                fetched = done()
                try? await Task.sleep(for: .milliseconds(500))
            }
        }
        if !online { throw Failure.noComputers }
        if !fetched { throw Failure.notFetched }
    }
}

/// What the share's member dials.
enum LiveShare {
    /// Whether addr is host:port with an IP address, as the member dials.
    static func numeric(_ addr: String) -> Bool {
        guard let (host, _) = JoinCode.split(addr) else { return false }
        return IPv4Address(host) != nil || IPv6Address(host) != nil
    }
}
