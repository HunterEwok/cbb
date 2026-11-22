// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// The group as the 0.6 member sees it (the member's `group` op and its
/// `state` event): who is the root, this device's place, whether the group
/// is stopped and its devices. The member evaluates the records; the app
/// only shows this. The Kotlin kit's GroupState is its twin.
public struct GroupState: Decodable, Equatable, Sendable {
    /// The Group ID, base64.
    public var group: String
    /// The current root's key hash, base64.
    public var root: String
    /// The root's device ID, empty while the root has none in the group.
    public var rootDevice: String
    public var me: Me
    /// none, secrets (no secrets are sealed) or full (nothing but the
    /// root's own records counts).
    public var stop: String
    /// The recovery chain has two records at one step, or one this version
    /// cannot read: the group stopped for good here.
    public var halted: Bool
    /// A recovery record this version cannot read: update the app.
    public var updateNeeded: Bool
    /// The settings ask for newer rules than this version's: no secrets here.
    public var tooOld: Bool
    /// A change of root is arriving: its records are not all here yet.
    public var changeArriving: Bool
    /// The group's key level (Records.keyLevels).
    public var keyLevel: String
    /// How long a copy and a secret live, in milliseconds; nil while no
    /// copies record sets it (D-129).
    public var ttlMS: Int64?
    public var secretTtlMS: Int64?
    public var devices: [Device]

    /// This device's place in the group.
    public struct Me: Decodable, Equatable, Sendable {
        public var device: String
        /// phone, computer, watch, board, … as the device record says.
        public var role: String
        /// The admin key the records name for it is one of the group's admins.
        public var admin: Bool
        public var frozen: Bool
        public var leaf: Bool

        enum CodingKeys: String, CodingKey { case device, role, admin, frozen, leaf }

        public init(device: String = "", role: String = "", admin: Bool = false, frozen: Bool = false, leaf: Bool = false) {
            (self.device, self.role, self.admin, self.frozen, self.leaf) = (device, role, admin, frozen, leaf)
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            device = try c.decodeIfPresent(String.self, forKey: .device) ?? ""
            role = try c.decodeIfPresent(String.self, forKey: .role) ?? ""
            admin = try c.decodeIfPresent(Bool.self, forKey: .admin) ?? false
            frozen = try c.decodeIfPresent(Bool.self, forKey: .frozen) ?? false
            leaf = try c.decodeIfPresent(Bool.self, forKey: .leaf) ?? false
        }
    }

    /// One device the group counts; removed devices are not listed.
    public struct Device: Decodable, Equatable, Sendable, Identifiable {
        public var device: String
        public var name: String
        public var os: String
        public var role: String
        /// The admin key the records name for it is one of the group's admins.
        public var admin: Bool
        public var frozen: Bool
        public var hub: Bool
        /// It offered this phone an admin key when it paired and is no admin
        /// yet: the root may make it one.
        public var offersAdmin: Bool

        public var id: String { device }

        enum CodingKeys: String, CodingKey { case device, name, os, role, admin, frozen, hub, offersAdmin = "offers_admin" }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            device = try c.decodeIfPresent(String.self, forKey: .device) ?? ""
            name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
            os = try c.decodeIfPresent(String.self, forKey: .os) ?? ""
            role = try c.decodeIfPresent(String.self, forKey: .role) ?? ""
            admin = try c.decodeIfPresent(Bool.self, forKey: .admin) ?? false
            frozen = try c.decodeIfPresent(Bool.self, forKey: .frozen) ?? false
            hub = try c.decodeIfPresent(Bool.self, forKey: .hub) ?? false
            offersAdmin = try c.decodeIfPresent(Bool.self, forKey: .offersAdmin) ?? false
        }
    }

    enum CodingKeys: String, CodingKey {
        case group, root, me, stop, halted, devices
        case rootDevice = "root_device"
        case updateNeeded = "update_needed"
        case tooOld = "too_old"
        case changeArriving = "change_arriving"
        case keyLevel = "key_level"
        case ttlMS = "ttl_ms"
        case secretTtlMS = "secret_ttl_ms"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        group = try c.decodeIfPresent(String.self, forKey: .group) ?? ""
        root = try c.decodeIfPresent(String.self, forKey: .root) ?? ""
        rootDevice = try c.decodeIfPresent(String.self, forKey: .rootDevice) ?? ""
        me = try c.decodeIfPresent(Me.self, forKey: .me) ?? Me()
        stop = try c.decodeIfPresent(String.self, forKey: .stop) ?? "none"
        halted = try c.decodeIfPresent(Bool.self, forKey: .halted) ?? false
        updateNeeded = try c.decodeIfPresent(Bool.self, forKey: .updateNeeded) ?? false
        tooOld = try c.decodeIfPresent(Bool.self, forKey: .tooOld) ?? false
        changeArriving = try c.decodeIfPresent(Bool.self, forKey: .changeArriving) ?? false
        keyLevel = try c.decodeIfPresent(String.self, forKey: .keyLevel) ?? Records.hardware
        ttlMS = try c.decodeIfPresent(Int64.self, forKey: .ttlMS)
        secretTtlMS = try c.decodeIfPresent(Int64.self, forKey: .secretTtlMS)
        devices = try c.decodeIfPresent([Device].self, forKey: .devices) ?? []
    }

    /// Nothing but the root's own records counts, or the group stopped for good.
    public var stopped: Bool { stop == "full" || halted }

    /// This device is the group's root.
    public var isRoot: Bool { !me.device.isEmpty && me.device == rootDevice }
}

/// A notice of the member (its `notices` op and `notice` event): something
/// the person should know about the group's records, such as a silent admin
/// or a change of root arriving. kind names it, args are its parameters,
/// which the app says in its own words.
public struct Notice: Decodable, Equatable, Sendable, Identifiable {
    public var id: String
    /// change_arriving, admins_silent, removal_warning, removals_waiting,
    /// root_room_waiting, ack_owed, frozen_holding, checkpoint_stuck,
    /// returned_after_removal or recovery_not_saved.
    public var kind: String
    public var args: [String: String]
    public var dismissable: Bool

    enum CodingKeys: String, CodingKey { case id, kind, args, dismissable }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? ""
        kind = try c.decodeIfPresent(String.self, forKey: .kind) ?? ""
        args = (try c.decodeIfPresent([String: Scalar].self, forKey: .args) ?? [:]).mapValues(\.text)
        dismissable = try c.decodeIfPresent(Bool.self, forKey: .dismissable) ?? true
    }

    /// A string, number or flag of args, as text.
    struct Scalar: Decodable {
        var text: String
        init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if let s = try? c.decode(String.self) {
                text = s
            } else if let n = try? c.decode(Int64.self) {
                text = String(n)
            } else if let b = try? c.decode(Bool.self) {
                text = String(b)
            } else {
                text = ""
            }
        }
    }
}

/// The list a change of root shows before it is signed ("who stays", the
/// member's `change_preview`): one row per device of the group, with what
/// the change does to it. The core writes the list; the person only
/// unticks devices, each untick a removal the new root signs in the same
/// act.
public struct ChangePreview: Decodable, Equatable, Sendable {
    public var rows: [Row]
    /// A change already waits for its records: sync first, and write over
    /// it only after that fails.
    public var waiting: Bool

    public struct Row: Decodable, Equatable, Sendable, Identifiable {
        public var device: String
        public var name: String
        public var os: String
        /// stays, out, admin_kept, admin_lost, frozen or removed_earlier.
        public var outcome: String
        /// Re-issued frozen: it acts only once the new root thaws it.
        public var frozen: Bool

        public var id: String { device }

        enum CodingKeys: String, CodingKey { case device, name, os, outcome, frozen }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            device = try c.decodeIfPresent(String.self, forKey: .device) ?? ""
            name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
            os = try c.decodeIfPresent(String.self, forKey: .os) ?? ""
            outcome = try c.decodeIfPresent(String.self, forKey: .outcome) ?? ""
            frozen = try c.decodeIfPresent(Bool.self, forKey: .frozen) ?? false
        }
    }

    enum CodingKeys: String, CodingKey { case rows, waiting }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        rows = try c.decodeIfPresent([Row].self, forKey: .rows) ?? []
        waiting = try c.decodeIfPresent(Bool.self, forKey: .waiting) ?? false
    }
}

/// The group's recovery key as the person gives it to a change of root: the
/// sheet's QR code, its typed text, or the secret a YubiKey opened.
public enum RecoveryInput: Encodable, Sendable {
    case qr(String)
    case text(String)
    case secret(Data)

    enum CodingKeys: String, CodingKey { case qr, text, secret }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .qr(s): try c.encode(s, forKey: .qr)
        case let .text(s): try c.encode(s, forKey: .text)
        case let .secret(d): try c.encode(d, forKey: .secret)
        }
    }
}
