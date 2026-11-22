// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import os
import SwiftUI
import UIKit
import UniformTypeIdentifiers

private let log = Logger(subsystem: "tools.cbb", category: "share")

/// Share and the text selection menu's Share: hands the text, the link, an
/// image or files to the app, which sends them to the group as its Home
/// button sends the clipboard, the next time it runs (docs/apps.md,
/// "Share").
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
                // Long enough to read that the app sends it.
                try? await Task.sleep(for: .seconds(3))
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
            case .sent:
                Image(systemName: "checkmark.circle").font(.largeTitle)
                Text("CBB sends it to your devices the next time you open it.").multilineTextAlignment(.center)
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

/// One share, handed to the app: the extension checks there is a group
/// and keeps what was shared in the app group (ShareQueue); the app's
/// member sends it the next time the app runs. The extension runs no member
/// of its own, since two members with one device key would fight over the
/// group's state.
@MainActor
enum OneShot {
    enum Failure: Error { case noGroup }

    /// What Share sends: a text, or images or files.
    enum What {
        case text(String)
        case media([CoreMember.Part])
    }

    static func send(_ what: What) async throws {
        guard try PhoneGroup.load(from: Shared.groupFile) != nil else { throw Failure.noGroup }
        switch what {
        case let .text(text):
            try ShareQueue.add(text: text)
        case let .media(parts):
            try ShareQueue.add(parts: parts.compactMap { p in p.data.map { ($0, p.type, p.path) } })
        }
    }
}
