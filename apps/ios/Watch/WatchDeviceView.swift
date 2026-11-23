// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// The emergency actions a watch that is an admin has for one device
/// (docs/protocol.md, section 10, "Watches"): each asks for a tap on what it
/// signs, then the watch signs it with its own key.
struct WatchDeviceView: View {
    let device: WatchState.Device
    @EnvironmentObject private var model: WatchModel
    @Environment(\.palette) private var palette
    /// The action waiting for the tap that confirms it, and its quick action.
    @State private var asking: (action: String, name: String?)?

    var body: some View {
        List {
            ForEach(device.can ?? [], id: \.self) { a in
                if a == "action" {
                    ForEach(device.actions ?? [], id: \.self) { n in
                        button(a, name: n)
                    }
                } else {
                    button(a, name: nil)
                }
            }
            if let note = model.actionNote {
                Text(verbatim: note).font(.caption2).foregroundStyle(model.actionDone ? palette.accent : palette.danger)
            }
        }
        .navigationTitle(Text(verbatim: device.name))
        .disabled(model.acting)
        .confirmationDialog(Text(question), isPresented: Binding(get: { asking != nil }, set: { if !$0 { asking = nil } })) {
            Button(role: .destructive) {
                guard let a = asking else { return }
                asking = nil
                Task { await model.run(a.action, on: device.id, name: a.name) }
            } label: {
                Text("Sign")
            }
        }
    }

    private func button(_ action: String, name: String?) -> some View {
        Button {
            asking = (action, name)
        } label: {
            title(action, name: name)
        }
    }

    private func title(_ action: String, name: String?) -> Text {
        switch action {
        case "freeze": Text("Freeze this admin")
        case "remove": Text("Remove from the group")
        case "paste-off": Text("Turn remote paste off")
        case "actions-off": Text("Turn quick actions off")
        case "away-off": Text("Turn sync away from home off")
        default: Text(verbatim: name ?? action)
        }
    }

    private var question: String {
        guard let a = asking else { return "" }
        let what = switch a.action {
        case "freeze": String(localized: "Freeze \(device.name)? It stays an admin in name, but nothing it signs counts until the main device unfreezes it.")
        case "remove": String(localized: "Remove \(device.name) from the group?")
        case "paste-off": String(localized: "Turn remote paste off on \(device.name)?")
        case "actions-off": String(localized: "Turn every quick action off on \(device.name)?")
        case "away-off": String(localized: "Turn sync away from home off on \(device.name)?")
        default: String(localized: "Run \(a.name ?? "") on \(device.name)?")
        }
        return what
    }
}
