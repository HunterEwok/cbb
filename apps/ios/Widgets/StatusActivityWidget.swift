// SPDX-License-Identifier: AGPL-3.0-only

import ActivityKit
import SwiftUI
import WidgetKit

/// The Dynamic Island and the Lock Screen of StatusActivity: an icon for
/// what runs, its line, and a timer while a device is added or the phone
/// syncs away from home.
struct StatusActivityWidget: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: StatusActivity.self) { context in
            StatusLockScreen(state: context.state)
                .activityBackgroundTint(ThemeChoice.theme(context.state.theme).dark.background)
        } dynamicIsland: { context in
            let state = context.state
            let accent = ThemeChoice.theme(state.theme).dark.accent
            return DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    StatusIcon(kind: state.kind).font(.title2).foregroundStyle(accent).padding(.leading, 4)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    StatusTimer(state: state).font(.body.monospacedDigit()).foregroundStyle(accent)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: "CBB").font(.caption).foregroundStyle(.secondary)
                        Text(verbatim: state.line).font(.headline).lineLimit(2)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            } compactLeading: {
                StatusIcon(kind: state.kind).foregroundStyle(accent)
            } compactTrailing: {
                StatusTimer(state: state).font(.caption2.monospacedDigit()).foregroundStyle(accent).frame(maxWidth: 44)
            } minimal: {
                StatusIcon(kind: state.kind).foregroundStyle(accent)
            }
            .keylineTint(accent)
        }
    }
}

struct StatusIcon: View {
    let kind: StatusActivity.Kind

    var body: some View {
        switch kind {
        case .adding: Image(systemName: "plus.circle.fill")
        case .away: Image(systemName: "lock.shield.fill")
        case .exchange: Image(systemName: "arrow.up.arrow.down.circle.fill")
        }
    }
}

/// The time since it started while a device is added or the tunnel runs; a
/// tick for a sync's result.
struct StatusTimer: View {
    let state: StatusActivity.ContentState

    var body: some View {
        if state.kind == .exchange {
            Image(systemName: "checkmark")
        } else {
            Text(timerInterval: state.since...Date.distantFuture, countsDown: false)
                .multilineTextAlignment(.trailing)
        }
    }
}

struct StatusLockScreen: View {
    let state: StatusActivity.ContentState

    var body: some View {
        let p = ThemeChoice.theme(state.theme).dark
        HStack(spacing: 12) {
            StatusIcon(kind: state.kind).font(.title).foregroundStyle(p.accent)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: "CBB").font(.caption).foregroundStyle(p.textDim)
                Text(verbatim: state.line).font(.headline).foregroundStyle(p.text).lineLimit(2)
            }
            Spacer()
            StatusTimer(state: state).font(.body.monospacedDigit()).foregroundStyle(p.accent)
        }
        .padding()
    }
}
