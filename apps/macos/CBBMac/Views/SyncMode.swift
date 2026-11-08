// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// A device's sync, on (mode shared) or off (mode own; docs/design.md,
/// "Sync on and off").
enum SyncMode: String, CaseIterable, Identifiable {
    case shared, own

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .shared: "On"
        case .own: "Off"
        }
    }
}
