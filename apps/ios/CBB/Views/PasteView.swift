// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import PhotosUI
import SwiftUI
import UIKit

/// Remote paste (docs/design.md, "Remote paste"): a text to put where a
/// computer's focus is, pasted or typed, with Enter after it if asked. The
/// computer takes it only when its user turned remote paste on there.
struct PasteView: View {
    let device: AppModel.Computer
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @State private var text = ""
    @State private var typing = false
    @State private var enter = false
    @State private var secret = false
    @State private var sending = false
    @State private var photo: PhotosPickerItem?
    @State private var importing = false
    @FocusState private var editing: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(String(localized: "Text", bundle: .app), text: $text, axis: .vertical)
                        .lineLimit(3...10)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .focused($editing)
                } footer: {
                    Text("It goes where \(device.name)'s keyboard focus is, once its user turned remote paste on there. Left empty, Paste sends what the clipboard holds.")
                }
                // Why the computer did not take it, right under the text, where
                // the keyboard does not hide it.
                if let message = model.message, !sending {
                    Section {
                        Text(message).foregroundStyle(palette.danger)
                    }
                }
                Section {
                    Toggle(isOn: $typing) { Text("Type it key by key") }
                    Toggle(isOn: $enter) { Text("Press Enter after it") }
                    Toggle(isOn: $secret) { Text("A secret") }
                } footer: {
                    Text("A paste suits most apps; typing suits those that take no paste, and only up to 4 KB. Enter runs a command in a terminal, so the computer takes it only when its user allowed that. A secret leaves no trace in the computer's log or clipboard.")
                }
                Section {
                    PhotosPicker(selection: $photo, matching: .images) { Text("Paste a picture…") }
                        .disabled(sending)
                    Button { importing = true } label: { Text("Paste files…") }
                        .disabled(sending)
                } footer: {
                    Text("A picture or files go to the group as a copy, and the computer pastes them where its focus is, as Cmd+V or Ctrl+V would: into a chat, a document or a folder. Enter, if on, sends them in a chat.")
                }
            }
            .onChange(of: photo) { _, item in
                guard let item else { return }
                photo = nil
                Task { await sendPhoto(item) }
            }
            .fileImporter(isPresented: $importing, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
                if case .success(let urls) = result { Task { await sendFiles(urls) } }
            }
            .navigationTitle(Text("Paste on \(device.name)"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if sending {
                        ProgressView()
                    } else {
                        Button { send() } label: { Text("Paste") }
                    }
                }
            }
            .onAppear { model.message = nil }
        }
    }

    /// Sends the field, or what the clipboard holds when the field is empty
    /// (iOS asks once whether the app may read it, unless its Settings allow it).
    private func send() {
        editing = false
        sending = true
        let typed = text
        Task {
            let text = typed.isEmpty ? await Self.clipboardText() : typed
            guard !text.isEmpty else {
                model.message = String(localized: "The clipboard holds no text.", bundle: .app)
                sending = false
                return
            }
            let done = await model.paste(device.id, text: text, method: typing ? "type" : "paste", enter: enter, secret: secret)
            sending = false
            if done { dismiss() }
        }
    }

    /// Sends a picked picture as an image, PNG or JPEG as Images makes it.
    private func sendPhoto(_ item: PhotosPickerItem) async {
        sending = true
        defer { sending = false }
        guard let data = try? await item.loadTransferable(type: Data.self), let image = UIImage(data: data),
              let copied = Self.image(data, image), Int64(copied.data.count) <= Images.maxCopy
        else {
            model.message = String(localized: "The picture could not be read, or is larger than 100 MB.", bundle: .app)
            return
        }
        if await model.pasteMedia(device.id, parts: [.data(copied.data, type: copied.type)], enter: enter) { dismiss() }
    }

    /// The picture as the group carries it: its own bytes when they are
    /// PNG or JPEG, else converted.
    private static func image(_ data: Data, _ image: UIImage) -> Images.Copied? {
        if data.starts(with: [0x89, 0x50, 0x4E, 0x47]) { return Images.Copied(type: "image/png", data: data) }
        if data.starts(with: [0xFF, 0xD8, 0xFF]) { return Images.Copied(type: "image/jpeg", data: data) }
        return Images.convert(image)
    }

    /// Sends picked files, read whole, at most 100 MB together.
    private func sendFiles(_ urls: [URL]) async {
        sending = true
        defer { sending = false }
        var parts: [CoreMember.Part] = []
        var total: Int64 = 0
        for url in urls {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            guard let data = try? Data(contentsOf: url) else {
                model.message = String(localized: "\(url.lastPathComponent) could not be read.", bundle: .app)
                return
            }
            total += Int64(data.count)
            guard total <= Images.maxCopy else {
                model.message = String(localized: "The files are larger than 100 MB together.", bundle: .app)
                return
            }
            parts.append(.bytes(data, path: url.lastPathComponent))
        }
        guard !parts.isEmpty else { return }
        if await model.pasteMedia(device.id, parts: parts, enter: enter) { dismiss() }
    }

    /// The clipboard's text, read off the main thread: the read waits while
    /// iOS asks the user to allow it, and on the main thread the app froze
    /// until the user answered.
    nonisolated static func clipboardText() async -> String {
        await Task.detached(priority: .userInitiated) { UIPasteboard.general.string ?? "" }.value
    }
}
