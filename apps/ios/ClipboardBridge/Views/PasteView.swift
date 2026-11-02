// SPDX-License-Identifier: AGPL-3.0-only

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
        let text = text.isEmpty ? (UIPasteboard.general.string ?? "") : text
        guard !text.isEmpty else {
            model.message = String(localized: "The clipboard holds no text.", bundle: .app)
            return
        }
        sending = true
        Task {
            let done = await model.paste(device.id, text: text, method: typing ? "type" : "paste", enter: enter, secret: secret)
            sending = false
            if done { dismiss() }
        }
    }
}
