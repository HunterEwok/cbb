// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// The one page: how many devices are online, the away switch, the devices
/// and the latest events.
struct WatchHome: View {
    @EnvironmentObject private var model: WatchModel
    @Environment(\.palette) private var palette

    var body: some View {
        NavigationStack {
            List {
                if model.state.hasGroup {
                    group
                } else {
                    Text("Open Clipboard Bridge on the iPhone to make or join a group.")
                        .foregroundStyle(palette.textDim)
                }
            }
            .navigationTitle(Text(verbatim: "CBB"))
        }
    }

    @ViewBuilder private var group: some View {
        let online = model.state.devices.filter(\.online).count
        Section {
            Text("\(online) of \(model.state.devices.count) online")
                .font(.headline)
            if let away = model.state.away {
                Toggle(isOn: Binding(get: { away != .off }, set: { model.setAway($0) })) {
                    Text("Away from home")
                }
                .disabled(model.switching)
                awayLine(away).font(.caption2).foregroundStyle(away == .connected ? palette.accent : palette.textDim)
            }
            if let note = model.note {
                Text(verbatim: note).font(.caption2).foregroundStyle(palette.danger)
            }
        }
        // The devices in no collection, then each of the phone's collections.
        ForEach(Array(model.state.sections.enumerated()), id: \.offset) { _, section in
            if section.name == nil || !section.devices.isEmpty {
                Section {
                    ForEach(section.devices) { d in
                        if model.admission != nil, !(d.can ?? []).isEmpty {
                            NavigationLink { WatchDeviceView(device: d) } label: { row(d) }
                        } else {
                            row(d)
                        }
                    }
                } header: {
                    if let name = section.name { Text(verbatim: name) } else { Text("Devices") }
                }
            }
        }
        if !model.state.events.isEmpty {
            Section {
                ForEach(Array(model.state.events.enumerated()), id: \.offset) { _, e in
                    Text(verbatim: e).font(.caption)
                }
            } header: {
                Text("Latest")
            }
        }
        if model.admission != nil {
            Text("This watch is an admin of the group.").font(.caption2).foregroundStyle(palette.textDim)
        }
        if !model.reachable {
            Text("As the iPhone last said.").font(.caption2).foregroundStyle(palette.textDim)
        }
    }

    private func row(_ d: WatchState.Device) -> some View {
        HStack {
            Image(systemName: d.symbol).foregroundStyle(palette.accent).frame(width: 24).accessibilityHidden(true)
            VStack(alignment: .leading) {
                Text(verbatim: d.name).lineLimit(1)
                if d.phone == true {
                    Text("This watch's iPhone").font(.caption2).foregroundStyle(palette.textDim)
                }
            }
            Spacer()
            Circle().fill(d.online ? palette.accent : palette.textDim.opacity(0.4)).frame(width: 8, height: 8)
        }
        .accessibilityElement(children: .combine)
        .accessibilityValue(d.online ? Text("online") : Text("offline"))
    }

    private func awayLine(_ away: WatchState.Away) -> Text {
        switch away {
        case .off: Text("Off")
        case .atHome: Text("At home: syncing directly.")
        case .connecting: Text("Connecting to the hub…")
        case .connected: Text("Through your hub.")
        case .waiting: Text("Waiting for the hub.")
        }
    }
}
