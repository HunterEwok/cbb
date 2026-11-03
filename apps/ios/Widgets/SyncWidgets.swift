// SPDX-License-Identifier: AGPL-3.0-only

import AppIntents
import SwiftUI
import WidgetKit

/// The home-screen widget and the Control Center control "Sync clipboard"
/// (docs/apps.md): one tap opens the app, which syncs as its Home button
/// does (OpenAndSyncIntent).
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

struct SyncControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: "tools.cbb.sync-control") {
            ControlWidgetButton(action: OpenAndSyncIntent()) {
                Label("Sync clipboard", systemImage: "arrow.up.arrow.down")
            }
        }
        .displayName("Sync clipboard")
        .description("Opens CBB and syncs the clipboard with your computers.")
    }
}
