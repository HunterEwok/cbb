// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// What moves between a device's clipboard and the group (docs/design.md,
/// "Sync modes").
enum SyncMode: String, CaseIterable, Identifiable {
    case own, shared, receive, send

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .own: "Own clipboard"
        case .shared: "Shared"
        case .receive: "Receive only"
        case .send: "Send only"
        }
    }

    /// What the mode does, in one line.
    var note: LocalizedStringKey {
        switch self {
        case .own: "Its copies stay on it and the group's do not come; sending or fetching by hand still works."
        case .shared: "Its copies go to the group, and the group's come to it."
        case .receive: "The group's copies come to it; its own stay on it."
        case .send: "Its copies go to the group; the group's do not come."
        }
    }
}
