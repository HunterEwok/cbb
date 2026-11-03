// SPDX-License-Identifier: AGPL-3.0-only

import ActivityKit
import Foundation
import os

private let log = Logger(subsystem: "tools.cbb", category: "island")

/// Starts and ends the Live Activities of StatusActivity. Each kind runs at
/// most once; a sync's result shows for a few seconds, then ends.
@MainActor
enum Island {
    /// How long the result of a sync stays.
    static let flashFor: Duration = .seconds(4)

    private static var color: String {
        UserDefaults.standard.string(forKey: AccentChoice.key) ?? Tokens.colors[0].name
    }

    private static func running(_ kind: StatusActivity.Kind) -> Activity<StatusActivity>? {
        Activity<StatusActivity>.activities.first { $0.content.state.kind == kind }
    }

    /// Shows kind with line, or updates the one that runs.
    static func show(_ kind: StatusActivity.Kind, _ line: String) {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        if let a = running(kind) {
            var state = a.content.state
            guard state.line != line || state.color != color else { return }
            (state.line, state.color) = (line, color)
            Task { await a.update(ActivityContent(state: state, staleDate: nil)) }
            return
        }
        let state = StatusActivity.ContentState(kind: kind, line: line, since: .now, color: color)
        do {
            _ = try Activity.request(attributes: StatusActivity(), content: ActivityContent(state: state, staleDate: nil))
        } catch {
            // Live Activities are a nicety: the app says the same itself.
            log.info("no Live Activity: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Ends kind, at once or after showing a last line for a moment.
    static func end(_ kind: StatusActivity.Kind, last line: String? = nil) {
        guard let a = running(kind) else { return }
        Task {
            if let line {
                var state = a.content.state
                state.line = line
                await a.update(ActivityContent(state: state, staleDate: nil))
                try? await Task.sleep(for: flashFor)
            }
            await a.end(nil, dismissalPolicy: .immediate)
        }
    }

    /// Shows the result of a sync for a moment.
    static func flash(_ line: String) {
        show(.exchange, line)
        end(.exchange, last: line)
    }
}
