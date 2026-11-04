// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import SwiftUI

/// What the group's records stop and what ends it, on Home: the stop, each
/// conflict and each claim (GroupAlert). On the root phone each comes with
/// what ends it, after Face ID: voiding both histories of a key, cancelling
/// a claim, or removing one of two admins that removed each other.
struct AlertsCard: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        if model.removed {
            RemovedCard()
        }
        if model.handedOver {
            HandedCard()
        }
        if !model.alerts.isEmpty {
            VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
                ForEach(model.alerts) { alert in
                    row(alert)
                }
            }
            .padding(Tokens.spacingMedium)
            .frame(maxWidth: .infinity, alignment: .leading)
            .glassCard()
        }
    }

    @ViewBuilder private func row(_ alert: GroupAlert) -> some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            Label {
                Text(verbatim: Self.text(alert))
            } icon: {
                Image(systemName: alert.kind == .newer ? "arrow.down.circle" : "exclamationmark.triangle")
            }
            .foregroundStyle(alert.kind == .newer ? palette.text : palette.danger)
            actions(alert)
        }
    }

    @ViewBuilder private func actions(_ alert: GroupAlert) -> some View {
        switch alert.kind {
        case .twoHistories where model.isRoot:
            Button { Task { await model.resolve(alert) } } label: { Text("Void both histories") }
                .buttonStyle(GlassButtonStyle())
                .disabled(model.busy)
        case .claims, .claimPending, .claimStopped:
            if model.isRoot {
                Button { Task { await model.resolve(alert) } } label: { Text("Cancel the claim") }
                    .buttonStyle(GlassButtonStyle())
                    .disabled(model.busy)
            } else {
                decides
            }
        case .admins where model.isRoot:
            ForEach(Array(zip(alert.devices, alert.names)), id: \.0) { id, name in
                Button(role: .destructive) { Task { await model.remove(id) } } label: { Text("Remove \(name)") }
                    .buttonStyle(GlassButtonStyle())
                    .disabled(model.busy)
            }
        case .twoHistories, .admins:
            decides
        case .stopped, .secretsStopped, .newer:
            EmptyView()
        }
    }

    private var decides: some View {
        Text("The group's root decides.").font(.footnote).foregroundStyle(palette.textDim)
    }

    /// The alert in a sentence.
    static func text(_ alert: GroupAlert) -> String {
        let who = alert.names.isEmpty
            ? String(localized: "devices unknown here", bundle: .app)
            : ListFormatter.localizedString(byJoining: alert.names)
        switch alert.kind {
        case .stopped:
            return String(localized: "The group is stopped: its devices exchange only their records, no clipboard, until the group's root decides.", bundle: .app)
        case .secretsStopped:
            return String(localized: "The group sends no secrets until its root decides.", bundle: .app)
        case .twoHistories:
            return String(localized: "\(who) signed two histories with one key, as a stolen key or a restore from a backup would.", bundle: .app)
        case .admins:
            return String(localized: "Admins removed or froze each other without seeing it: \(who). The root removes one of them.", bundle: .app)
        case .claims:
            return String(localized: "Two claims to take the group over: \(who).", bundle: .app)
        case .claimPending:
            guard let ms = alert.leftMS, ms > 0 else {
                return String(localized: "\(who) claims the group, to take it over from its root.", bundle: .app)
            }
            let f = DateComponentsFormatter()
            f.unitsStyle = .full
            f.maximumUnitCount = 1
            f.allowedUnits = [.day, .hour, .minute]
            let left = f.string(from: Double(ms) / 1000) ?? ""
            return String(localized: "\(who) claims the group, to take it over from its root: it takes effect in \(left).", bundle: .app)
        case .claimStopped:
            return String(localized: "\(who) claims the group, and the group is stopped until its root decides.", bundle: .app)
        case .newer:
            return String(localized: "The group holds \(alert.count) records of a later version: update the app to read them.", bundle: .app)
        }
    }
}

/// The root handed the group to this phone (cbb handover): the button that
/// takes it, after Face ID.
struct HandedCard: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            Text("The group is yours to take")
                .font(.headline)
                .foregroundStyle(palette.text)
            Text("The computer that held the group handed it to this phone. Take it to make this phone the group's root; the computer stays in the group.")
                .font(.subheadline)
                .foregroundStyle(palette.textDim)
            Button("Take the group") {
                busy = true
                Task {
                    await model.takeHandedGroup()
                    busy = false
                }
            }
            .buttonStyle(AccentButtonStyle())
            .disabled(busy)
        }
        .padding(Tokens.spacingMedium)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard()
    }
}
