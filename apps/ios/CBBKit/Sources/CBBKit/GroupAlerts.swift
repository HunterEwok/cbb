// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// What the group's records stop and what ends it, for the apps to show
/// (docs/protocol.md, section 10, "Stopping the exchange"): the group's
/// stop, each conflict, each claim that waits or stops the group, and the
/// records of a later version. The root ends a conflict or a claim with a
/// resolve of records, or by removing a device.
public struct GroupAlert: Equatable, Sendable, Identifiable {
    public enum Kind: String, Sendable {
        /// Every member exchanges records only.
        case stopped
        /// No member sends a secret.
        case secretsStopped
        /// A key signed two histories: the root voids both (records).
        case twoHistories
        /// Admins removed or froze each other: the root removes one (devices).
        case admins
        /// Two claims under one root: the root cancels one or both (records).
        case claims
        /// A claim waits (leftMS) unless the root cancels it (records).
        case claimPending
        /// A claim that another admin removed or that competes with
        /// another: the group stops until the root cancels it (records).
        case claimStopped
        /// Records of a later version: update the app (count).
        case newer
    }

    public var kind: Kind
    /// The names of the devices involved, and their IDs, those known here.
    public var names: [String] = []
    public var devices: [String] = []
    /// The records a resolve names to end it.
    public var records: [Data] = []
    /// How long a pending claim waits still; nil when this device does not
    /// know yet.
    public var leftMS: Int64?
    public var count = 0

    public var id: String { kind.rawValue + ":" + devices.joined(separator: ",") + records.map { $0.base64EncodedString() }.joined() }
}

public extension RecordSet {
    /// The device of a signer's key: the device whose admin key it is, or
    /// the root's own device for a root's key.
    func device(ofSigner k: Data) -> Device? {
        if let d = devices.first(where: { $0.adminKey == k }) { return d }
        if view.state.roots.contains(k), let root = rootDevice { return devices.first { $0.id == root } }
        return nil
    }

    /// The alerts of the state, in the order the apps show them.
    var alerts: [GroupAlert] {
        let st = view.state
        var out: [GroupAlert] = []
        switch st.stop {
        case "full": out.append(GroupAlert(kind: .stopped))
        case "secrets": out.append(GroupAlert(kind: .secretsStopped))
        default: break
        }
        func involved(_ keys: [Data]) -> (names: [String], ids: [String]) {
            let ds = keys.compactMap { device(ofSigner: $0) }
            return (ds.map(\.name), ds.map(\.id))
        }
        for c in st.conflicts ?? [] {
            let who = involved(c.signers)
            let kind: GroupAlert.Kind
            switch c.kind {
            case "two_histories": kind = .twoHistories
            case "admins": kind = .admins
            case "claims": kind = .claims
            default: continue
            }
            out.append(GroupAlert(kind: kind, names: who.names, devices: who.ids, records: c.records))
        }
        for c in st.claims ?? [] {
            let who = involved([c.claimant])
            switch c.state {
            case "pending":
                out.append(GroupAlert(kind: .claimPending, names: who.names, devices: who.ids, records: [c.record], leftMS: c.left_ms))
            case "disputed", "competing":
                out.append(GroupAlert(kind: .claimStopped, names: who.names, devices: who.ids, records: [c.record]))
            default:
                break
            }
        }
        if let n = st.newer?.count, n > 0 { out.append(GroupAlert(kind: .newer, count: n)) }
        return out
    }
}
