// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// Sync away from home and the group's relay on a group of 0.6 (docs/apps.md,
/// "Away from home"). The Live member runs the tunnel and the link to the
/// relay in the app's process, in user space, and keeps their keys itself;
/// the app maps where the member says they stand (`CoreMember.AwayState`)
/// onto its cards. The relay is the group's setting, which the root writes;
/// every device meets the others there. A phone is no hub (D-134).
public enum AwayOn06 {
    /// Where sync away from home stands, as Settings shows it: off;
    /// waiting until a hub offered its tunnel; through it; or at home,
    /// where the member reaches the hub without it.
    public static func awayStatus(_ a: CoreMember.AwayState?, reached: (String) -> Bool) -> AwayFromHome.Status {
        guard let a else { return .off }
        if a.through { return .connected }
        if a.hubDevice.isEmpty { return .waitingForHub }
        return reached(a.hubDevice) ? .atHome : .connecting
    }

    /// Where the link to the group's relay stands, with the reason it
    /// failed; off while the group has no relay or sync away from home is off.
    public static func relayStatus(_ a: CoreMember.AwayState?) -> (RelayOnPhone.Status, String?) {
        guard let r = a?.relay else { return (.off, nil) }
        if r.connected { return (.connected, nil) }
        if !r.error.isEmpty { return (.failed, reason(r.error, r.detail)) }
        return (.connecting, nil)
    }

    /// The error with its underlying cause, for the log and for the error's details.
    public static func reason(_ error: String, _ detail: String) -> String {
        detail.isEmpty || detail == error ? error : "\(error) (\(detail))"
    }
}
