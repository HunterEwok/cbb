// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// The phone at the group's blind relay (docs/design.md, "Blind relay",
/// D-68), as the screens show it. On a group of 0.6 the Live member meets
/// the relay the group's root set (AwayOn06); a phone in a group of 0.5
/// meets no relay (D-123).
public enum RelayOnPhone {
    /// What the screens show.
    public enum Status: Sendable, Equatable { case off, paused, connecting, connected, failed }

    /// The relay's address is no "ip:port", or its key no pin.
    public enum Failure: Error, Equatable { case badRelay }
}
