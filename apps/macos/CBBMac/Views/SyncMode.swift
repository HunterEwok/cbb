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
}
