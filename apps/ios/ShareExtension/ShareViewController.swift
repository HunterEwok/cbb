// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
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
        let store = ServedContent()
        if media.count == 1, media[0].hasItemConformingToTypeIdentifier(UTType.image.identifier) {
            guard let image = await Images.load(media[0]), image.data.count <= maxShared else { throw TooLarge() }
            return .media(Content.manifest(store: store.memory, data: [(image.type, image.data)]), store)
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
        return .media(Content.files(store: store.memory, files: files), store)
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

/// One send: dials the computers of the group that browsing finds, as the
/// app does, and hands them the text once one is connected.
@MainActor
enum OneShot {
    enum Failure: Error { case noGroup, noKey, noComputers, notFetched }

    /// What Share sends: a text, or images or files with the store that
    /// serves them.
    enum What {
        case text(String)
        case media(Media.Manifest, ServedContent)
    }

    /// Holds the dialer for the browser's callback, which comes first.
    private final class DialerRef: @unchecked Sendable { var dialer: MemberDialer? }

    static func send(_ what: What, wait: Duration = .seconds(8), fetchWait: Duration = .seconds(60)) async throws {
        guard let g = try PhoneGroup.load(from: Shared.groupFile) else { throw Failure.noGroup }
        guard let key = try KeychainIdentity.loadKey(label: Shared.memberLabel) else { throw Failure.noKey }
        KeychainIdentity.removeCertificates(label: Shared.memberLabel)
        let id = try KeychainIdentity.identity(certificate: g.memberCert, key: key, label: Shared.memberLabel, storeKey: false)
        // The copy is sealed to the group's readers and signed, as the app's.
        let records = g.records
        let copies = CopyKeys(device: g.device, cert: g.memberCert, issuer: g.memberIssuer, signer: try SecKeySigner(key),
                              secret: try SealKey.secret(), records: { records })
        let node = MemberNode(engine: SyncEngine(device: g.device, clock: HybridClock()), name: UIDevice.current.name, os: "ios",
                              device: Member.DeviceInfo(form: UIDevice.current.userInterfaceIdiom == .pad ? "tablet" : "phone",
                                                        osVersion: UIDevice.current.systemVersion),
                              content: { () -> ContentStore? in if case let .media(_, s) = what { return s } else { return nil } }(),
                              copies: copies)
        let ref = DialerRef()
        let browser = BonjourBrowser { found in Task { await ref.dialer?.update(found) } }
        let dialer = MemberDialer(node: node, group: g.tag,
                                  dial: browser.dialer(identity: id, chain: g.memberIssuer.map { [$0] } ?? [], roots: g.trusted))
        ref.dialer = dialer
        browser.start()
        let deadline = ContinuousClock.now + wait
        var online = await node.connected
        while online.isEmpty, ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(200))
            online = await node.connected
        }
        var fetched = true
        if !online.isEmpty {
            switch what {
            case let .text(text):
                _ = try await node.send(text: text, kind: .text)
                // The event goes out on the connections; give them a moment.
                try? await Task.sleep(for: .seconds(1))
            case let .media(m, store):
                let e = try await node.send(text: "", kind: .text, media: m)
                // The computers fetch the copy's sealed blob from this phone.
                let blob = e.sealed?.blob
                let end = ContinuousClock.now + fetchWait
                while !store.served(blob), ContinuousClock.now < end { try? await Task.sleep(for: .milliseconds(200)) }
                fetched = store.served(blob)
                try? await Task.sleep(for: .milliseconds(500))
            }
        }
        await dialer.stop()
        browser.stop()
        await node.closeAll()
        if online.isEmpty { throw Failure.noComputers }
        if !fetched { throw Failure.notFetched }
    }
}

/// The parts Share sends, which notes how far each was read, so the
/// extension stays until a computer fetched them all.
final class ServedContent: ContentStore, @unchecked Sendable {
    let memory = MemoryContent(maxBytes: Int64(ShareModel.maxShared))
    private let lock = NSLock()
    private var ends: [Data: Int64] = [:]

    func open(sha256: Data) -> ContentSource? {
        memory.open(sha256: sha256).map { Source(inner: $0, sum: sha256, store: self) }
    }

    func sealBlob(_ m: Media.Manifest) throws -> (key: Data, blob: Media.Blob)? { try memory.sealBlob(m) }

    func note(_ sum: Data, end: Int64) { lock.withLock { ends[sum] = max(ends[sum] ?? 0, end) } }

    /// Whether the copy's sealed blob was read to its end; a copy of no
    /// bytes has none.
    func served(_ blob: Media.Blob?) -> Bool {
        guard let blob else { return true }
        return lock.withLock { (ends[blob.sha256] ?? 0) >= blob.size }
    }

    struct Source: ContentSource {
        let inner: ContentSource
        let sum: Data
        let store: ServedContent
        var size: Int64 { inner.size }
        func read(offset: Int64, length: Int) throws -> Data {
            let d = try inner.read(offset: offset, length: length)
            store.note(sum, end: offset + Int64(length))
            return d
        }
        func close() { inner.close() }
    }
}
