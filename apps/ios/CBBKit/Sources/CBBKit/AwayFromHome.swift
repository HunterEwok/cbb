// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

/// Sync away from home (docs/design.md, "Sync away from home"), as the
/// screens show it, which the Live member runs (AwayOn06).
public enum AwayFromHome {
    /// What the screens show.
    public enum Status: Sendable { case off, waitingForHub, atHome, connecting, connected }
}
