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

    private static var theme: String {
        UserDefaults.standard.string(forKey: ThemeChoice.key) ?? Tokens.themes[0].name
    }

    /// The activities that run, by kind. Reading Activity.activities asks
    /// the system synchronously, so the app reads it once, away from the
    /// main thread, and then keeps the list itself: a refresh of the model
    /// calls show or end every time, and a sync answer on the main thread
    /// can hold the screen while the system service is slow (as on a
    /// simulator that has just booted).
    private static var known: [StatusActivity.Kind: Activity<StatusActivity>] = [:]
    private static var loaded = false
    private static var waiting: [@MainActor () -> Void] = []

    private static func running(_ kind: StatusActivity.Kind) -> Activity<StatusActivity>? {
        known[kind]
    }

    /// Runs body once the activities of an earlier run of the app are
    /// known; calls made before that run afterwards, in their order.
    private static func whenLoaded(_ body: @escaping @MainActor () -> Void) {
        if loaded { return body() }
        waiting.append(body)
        guard waiting.count == 1 else { return }
        Task {
            let all = await Task.detached { Activity<StatusActivity>.activities }.value
            for a in all where known[a.content.state.kind] == nil { track(a) }
            loaded = true
            let calls = waiting
            waiting = []
            calls.forEach { $0() }
        }
    }

    /// Keeps a, and lets it go when it ends, whoever ends it.
    private static func track(_ a: Activity<StatusActivity>) {
        let kind = a.content.state.kind
        known[kind] = a
        Task {
            for await state in a.activityStateUpdates where state == .ended || state == .dismissed {
                if known[kind]?.id == a.id { known[kind] = nil }
                break
            }
        }
    }

    /// Shows kind with line, or updates the one that runs.
    static func show(_ kind: StatusActivity.Kind, _ line: String) {
        whenLoaded { showNow(kind, line) }
    }

    private static func showNow(_ kind: StatusActivity.Kind, _ line: String) {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        if let a = running(kind) {
            var state = a.content.state
            guard state.line != line || state.theme != theme else { return }
            (state.line, state.theme) = (line, theme)
            Task { await a.update(ActivityContent(state: state, staleDate: nil)) }
            return
        }
        let state = StatusActivity.ContentState(kind: kind, line: line, since: .now, theme: theme)
        do {
            track(try Activity.request(attributes: StatusActivity(), content: ActivityContent(state: state, staleDate: nil)))
        } catch {
            // Live Activities are a nicety: the app says the same itself.
            log.info("no Live Activity: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Ends kind, at once or after showing a last line for a moment.
    static func end(_ kind: StatusActivity.Kind, last line: String? = nil) {
        whenLoaded { endNow(kind, last: line) }
    }

    private static func endNow(_ kind: StatusActivity.Kind, last line: String?) {
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
