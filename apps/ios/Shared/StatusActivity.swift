// SPDX-License-Identifier: AGPL-3.0-only

import ActivityKit
import Foundation

/// The Live Activity in the Dynamic Island and on the Lock Screen
/// (docs/apps.md, "Dynamic Island"): a device being added, sync away from
/// home through the hub, or the result of a sync for a moment. It never
/// shows what was copied.
struct StatusActivity: ActivityAttributes {
    enum Kind: String, Codable, Hashable {
        case adding, away, exchange
    }

    struct ContentState: Codable, Hashable {
        var kind: Kind
        /// One line in the user's language, from the app.
        var line: String
        /// Since when it runs, for the timer of adding and away.
        var since: Date
        /// The theme chosen in Settings, by its name in Tokens.themes.
        var theme: String
    }
}
