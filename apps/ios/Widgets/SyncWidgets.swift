// SPDX-License-Identifier: AGPL-3.0-only

import AppIntents
import SwiftUI
import WidgetKit

/// The home-screen widget "Sync clipboard" (docs/apps.md): one tap opens
/// the app, which syncs as it does when it comes to the front
/// (OpenAndSyncIntent); and the house in Control Center (SyncControl).
@main
struct SyncWidgets: WidgetBundle {
    var body: some Widget {
        SyncWidget()
        SyncControl()
        StatusActivityWidget()
    }
}

struct SyncWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "tools.cbb.sync", provider: SyncProvider()) { _ in
            SyncWidgetView()
        }
        .configurationDisplayName("Sync clipboard")
        .description("Sends what this phone copied to your computers, or fetches what a computer copied a moment ago.")
        .supportedFamilies([.systemSmall, .accessoryCircular])
    }
}

struct SyncEntry: TimelineEntry {
    let date: Date
}

/// The widget shows no data, so one entry is enough.
struct SyncProvider: TimelineProvider {
    func placeholder(in context: Context) -> SyncEntry { SyncEntry(date: .now) }
    func getSnapshot(in context: Context, completion: @escaping (SyncEntry) -> Void) { completion(SyncEntry(date: .now)) }
    func getTimeline(in context: Context, completion: @escaping (Timeline<SyncEntry>) -> Void) {
        completion(Timeline(entries: [SyncEntry(date: .now)], policy: .never))
    }
}

struct SyncWidgetView: View {
    @Environment(\.widgetFamily) private var family

    var body: some View {
        Button(intent: OpenAndSyncIntent()) {
            VStack(spacing: 8) {
                Image(systemName: "arrow.up.arrow.down").font(.title)
                if family == .systemSmall {
                    Text("Sync clipboard").font(.headline).multilineTextAlignment(.center)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .buttonStyle(.plain)
        .containerBackground(.fill.tertiary, for: .widget)
    }
}

/// The house in Control Center (docs/apps.md): a tap turns sync on this
/// phone on or off; on, the control is lit with a filled clipboard, off, it
/// is grey with an empty one. iOS gives a control no long press of its own.
struct SyncControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: SyncSwitch.kind, provider: SyncValue()) { on in
            ControlWidgetToggle("Sync", isOn: on, action: SetSyncIntent()) { on in
                Label(on ? "On" : "Off", systemImage: on ? "list.clipboard.fill" : "clipboard")
            }
        }
        .displayName("Sync")
        .description("Turns sync on this phone on or off.")
    }
}

/// What the control shows: the app's state from the shared settings, off
/// without a group.
struct SyncValue: ControlValueProvider {
    var previewValue: Bool { true }
    func currentValue() async throws -> Bool { SyncSwitch.isOn ?? false }
}
