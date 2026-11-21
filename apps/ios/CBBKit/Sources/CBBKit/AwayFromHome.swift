// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

/// Sync away from home (docs/design.md, "Sync away from home"), as the
/// screens show it. On a group of 0.6 the Live member runs it (AwayOn06); a
/// phone in a group of 0.5 syncs at home only (D-123).
public enum AwayFromHome {
    /// What the screens show.
    public enum Status: Sendable { case off, waitingForHub, atHome, connecting, connected }
}
