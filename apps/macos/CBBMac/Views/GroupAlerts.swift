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

/// The member's notices about the group (docs/apps.md, "Notices"), as the
/// phones show them: each in a sentence, with Hide when it may be hidden.
struct GroupNotices: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.palette) private var palette

    var body: some View {
        let names = Dictionary(model.devices.map { ($0.id, $0.name) }, uniquingKeysWith: { a, _ in a })
        let shown = (model.status?.notices ?? []).compactMap { n in Self.text(n, names: names).map { Shown(notice: n, text: $0) } }
        if !shown.isEmpty {
            VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
                ForEach(shown) { s in
                    HStack(alignment: .firstTextBaseline) {
                        Label { Text(verbatim: s.text).fixedSize(horizontal: false, vertical: true) } icon: { Image(systemName: "info.circle") }
                            .foregroundStyle(palette.text)
                        Spacer()
                        if s.notice.dismissable == true {
                            Button { Task { await model.dismiss(s.notice) } } label: { Text("Hide") }
                                .disabled(model.busy)
                        }
                    }
                }
            }
            .padding(Tokens.spacingMedium)
            .frame(maxWidth: .infinity, alignment: .leading)
            .glassCard()
        }
    }

    /// A notice this app shows, with its sentence.
    struct Shown: Identifiable {
        let notice: Control.Notice
        let text: String
        var id: String { notice.id }
    }

    /// The notice in a sentence, with the devices by name; nil for a kind
    /// this app does not show.
    static func text(_ n: Control.Notice, names: [String: String]) -> String? {
        let device = n.args?.device.map { names[$0] ?? $0 } ?? ""
        switch n.kind {
        case "change_arriving":
            return String(localized: "A change of the group's main device is on its way.")
        case "removals_waiting":
            return String(localized: "Removals wait until every admin has seen them.")
        case "root_room_waiting":
            let share = "\(n.args?.percent ?? 0)%"
            return String(localized: "Removals that wait for admins fill \(share) of the main device's room for records: bring those admins online.")
        case "ack_owed":
            return String(localized: "This Mac has a removal to confirm; it does so with your next admin action.")
        case "frozen_holding":
            return String(localized: "The frozen admin \(device) holds removals back: unfreeze it or remove it.")
        case "checkpoint_stuck":
            return String(localized: "The main device's records wait for records no device has passed on.")
        case "returned_after_removal":
            return String(localized: "\(device) was removed before the main device changed, and counts again now: remove it again if it should not be in the group.")
        default:
            return nil
        }
    }
}
