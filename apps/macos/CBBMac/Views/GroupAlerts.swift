// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// What the group's records stop and what ends it, from cbb status: the
/// stop and each conflict (docs/protocol.md, section 10,
/// "Stopping the exchange"). On the group's root it offers what ends each:
/// cbb resolve for two histories, removing an admin for the others.
struct GroupAlerts: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.palette) private var palette

    private var lines: [Line] { Self.lines(model.status) }

    var body: some View {
        if !lines.isEmpty {
            VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
                ForEach(lines) { line in
                    Label { Text(verbatim: line.text) } icon: { Image(systemName: "exclamationmark.triangle") }
                        .foregroundStyle(palette.danger)
                    if line.unmute {
                        if model.isAdmin, let me = model.this {
                            Button { Task { await model.unmute(me.id) } } label: { Text("Unmute") }
                                .disabled(model.busy)
                        } else {
                            Text("An admin of the group ends it.").font(.callout).foregroundStyle(palette.textDim)
                        }
                    } else if model.isRoot {
                        HStack {
                            if line.resolve {
                                Button { Task { await model.resolve() } } label: { Text("Void both histories") }
                            }
                            ForEach(line.remove, id: \.self) { name in
                                Button(role: .destructive) { Task { await model.remove(name) } } label: { Text("Remove \(name)") }
                            }
                        }
                        .disabled(model.busy)
                    } else if line.resolve || !line.remove.isEmpty {
                        Text("The group's main device decides.").font(.callout).foregroundStyle(palette.textDim)
                    }
                }
            }
            .padding(Tokens.spacingMedium)
            .frame(maxWidth: .infinity, alignment: .leading)
            .glassCard()
        }
    }

    /// An alert: its sentence, whether cbb resolve ends it, and the devices
    /// whose removal does.
    struct Line: Identifiable {
        var text: String
        var resolve = false
        var remove: [String] = []
        /// An admin's mute of this Mac, which an admin ends.
        var unmute = false
        var id: String { text }
    }

    static func lines(_ st: Control.Status?) -> [Line] {
        guard let st else { return [] }
        var out: [Line] = []
        switch st.stop {
        case "full":
            out.append(Line(text: String(localized: "The group is stopped: its devices exchange only their records, no clipboard, until the group's main device decides.")))
        case "secrets":
            out.append(Line(text: String(localized: "The group sends no secrets until its owner decides.")))
        default:
            break
        }
        for c in st.conflicts ?? [] {
            let who = c.devices.isEmpty ? String(localized: "devices unknown here") : ListFormatter.localizedString(byJoining: c.devices)
            switch c.kind {
            case "two_histories":
                out.append(Line(text: String(localized: "\(who) signed two histories with one key, as a stolen key or a restore from a backup would."), resolve: true))
            case "admins":
                out.append(Line(text: String(localized: "Admins removed or froze each other without seeing it: \(who). The main device removes one of them."), remove: c.devices))
            default:
                break
            }
        }
        if st.muted == true {
            if let until = MacModel.date(ms: st.mutedUntilMS) {
                out.append(Line(text: String(localized: "An admin muted this Mac until \(until.formatted(date: .abbreviated, time: .shortened)): its copies do not reach the group."), unmute: true))
            } else {
                out.append(Line(text: String(localized: "An admin muted this Mac: its copies do not reach the group until an admin unmutes it."), unmute: true))
            }
        }
        if let n = st.newer, n > 0 {
            out.append(Line(text: String(localized: "The group holds \(n) records of a later version: update CBB to read them.")))
        }
        return out
    }
}
