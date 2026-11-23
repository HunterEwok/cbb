// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CBBKit
import SwiftUI

/// The member's notices about the group, on Home (docs/apps.md, "Notices"):
/// each in a sentence, with a button that hides it when it may be hidden.
struct NoticesCard: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        let shown = model.notices.filter { Self.text($0, names: names) != nil }
        if !shown.isEmpty {
            VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
                ForEach(shown) { n in
                    HStack(alignment: .firstTextBaseline) {
                        Label {
                            Text(verbatim: Self.text(n, names: names) ?? "")
                                // Wraps to its full height instead of being clipped.
                                .fixedSize(horizontal: false, vertical: true)
                        } icon: {
                            Image(systemName: "info.circle")
                        }
                        .foregroundStyle(palette.text)
                        Spacer()
                        if n.dismissable {
                            Button { Task { await model.dismiss(notice: n) } } label: {
                                Image(systemName: "xmark")
                                    // A target a finger hits: 44 points square.
                                    .frame(minWidth: 44, minHeight: 44)
                                    .contentShape(Rectangle())
                                    .accessibilityLabel(Text("Hide"))
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(palette.textDim)
                        }
                    }
                }
            }
            .padding(Tokens.spacingMedium)
            .frame(maxWidth: .infinity, alignment: .leading)
            .glassCard()
        }
    }

    /// The devices' names by ID.
    private var names: [String: String] { Dictionary(model.devices.map { ($0.id, $0.name) }, uniquingKeysWith: { a, _ in a }) }

    /// The notice in a sentence; nil for a kind this app does not show.
    static func text(_ n: Notice, names: [String: String]) -> String? {
        let device = n.args["device"].map { names[$0] ?? $0 } ?? ""
        switch n.kind {
        case "change_arriving":
            return String(localized: "A change of the group's main device is on its way.", bundle: .app)
        case "admins_silent":
            let days = Int(n.args["days_left"] ?? "") ?? 0
            return days > 0
                ? String(localized: "No word from the admin \(device) for a long time: its admin rights end in \(days) days unless it connects.", bundle: .app)
                : String(localized: "No word from the admin \(device) for a long time: its admin rights end now.", bundle: .app)
        case "removals_waiting":
            return String(localized: "Removals wait until every admin has seen them.", bundle: .app)
        case "root_room_waiting":
            let share = (n.args["percent"] ?? "") + "%"
            return String(localized: "Removals that wait for admins fill \(share) of the main device's room for records: bring those admins online.", bundle: .app)
        case "ack_owed":
            return String(localized: "This phone has a removal to confirm; it does so with your next admin action.", bundle: .app)
        case "frozen_holding":
            return String(localized: "The frozen admin \(device) holds removals back: unfreeze it or remove it.", bundle: .app)
        case "checkpoint_stuck":
            return String(localized: "The main device's records wait for records no device has passed on.", bundle: .app)
        case "returned_after_removal":
            return String(localized: "\(device) was removed before the main device changed, and counts again now: remove it again if it should not be in the group.", bundle: .app)
        case "recovery_not_saved":
            return String(localized: "The group's recovery key is not saved yet: without it, losing this phone means making the group again.", bundle: .app)
        default:
            return nil
        }
    }
}

/// The group's root changed, on every device, until the person has seen it
/// (docs/apps.md, "Changing the main device"): who is the main device now,
/// and "This wasn't me", which explains what to do.
struct RootChangedCard: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @State private var notMe = false

    var body: some View {
        if let c = model.rootChanged {
            VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
                Text("The group's main device changed")
                    .font(.headline)
                    .foregroundStyle(palette.text)
                Text("\(c.to) is now the group's main device, in place of \(c.from).")
                    .font(.subheadline)
                    .foregroundStyle(palette.textDim)
                HStack {
                    Button { model.rootChangeSeen() } label: { Text("OK") }
                        .buttonStyle(GlassButtonStyle())
                    Button(role: .destructive) { notMe = true } label: { Text("This wasn't me") }
                        .buttonStyle(GlassButtonStyle())
                }
            }
            .padding(Tokens.spacingMedium)
            .frame(maxWidth: .infinity, alignment: .leading)
            .glassCard()
            .alert(Text("Someone has the group's recovery key"), isPresented: $notMe) {
                Button(role: .destructive) {
                    Task {
                        _ = await model.leave()
                        model.rootChangeSeen()
                    }
                } label: { Text("Leave the group") }
                Button(role: .cancel) {} label: { Text("Cancel") }
            } message: {
                Text("Only the recovery key changes the main device, and nothing undoes it. Leave the group on each of your devices, then make a new group and join them to it.")
            }
        }
    }
}
