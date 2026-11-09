// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// The device tiles as the member answers `view` and `arrange`
/// (docs/apps.md, "What the member shows"): the member keeps the user's
/// order and collections (`cbb_core::arrange`), and the apps only draw them
/// and send the user's changes.
public enum Arrangement {
    /// A collection's name has at most so many bytes.
    public static let maxName = 64

    /// A named collection of devices, one level only, by their IDs.
    public struct Collection: Codable, Equatable, Hashable, Sendable {
        public var id: String
        public var name: String
        public var devices: [String]

        public init(id: String, name: String, devices: [String]) {
            (self.id, self.name, self.devices) = (id, name, devices)
        }
    }

    /// A device or a collection, as a change names it.
    public enum Ref: Equatable, Hashable, Sendable, Encodable {
        case device(String)
        case collection(String)

        private enum Keys: String, CodingKey { case device, collection }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: Keys.self)
            switch self {
            case .device(let d): try c.encode(d, forKey: .device)
            case .collection(let id): try c.encode(id, forKey: .collection)
            }
        }
    }

    /// A change the user makes, which the member applies and keeps; it
    /// encodes as `arrange` takes it (cbb_core::arrange::Op).
    public enum Op: Equatable, Sendable, Encodable {
        case move(Ref, before: Ref?)
        case into(device: String, collection: String)
        case out(device: String)
        case new(name: String, devices: [String])
        case rename(collection: String, name: String)
        case ungroup(collection: String)
        case reset

        private enum Keys: String, CodingKey { case op, item, before, device, collection, name, devices }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: Keys.self)
            switch self {
            case let .move(item, before):
                try c.encode("move", forKey: .op)
                try c.encode(item, forKey: .item)
                try c.encodeIfPresent(before, forKey: .before)
            case let .into(device, collection):
                try c.encode("into", forKey: .op)
                try c.encode(device, forKey: .device)
                try c.encode(collection, forKey: .collection)
            case let .out(device):
                try c.encode("out", forKey: .op)
                try c.encode(device, forKey: .device)
            case let .new(name, devices):
                try c.encode("new", forKey: .op)
                try c.encode(name, forKey: .name)
                try c.encode(devices, forKey: .devices)
            case let .rename(collection, name):
                try c.encode("rename", forKey: .op)
                try c.encode(collection, forKey: .collection)
                try c.encode(name, forKey: .name)
            case let .ungroup(collection):
                try c.encode("ungroup", forKey: .op)
                try c.encode(collection, forKey: .collection)
            case .reset:
                try c.encode("reset", forKey: .op)
            }
        }

        /// The change as JSON.
        public var data: Data {
            let e = JSONEncoder()
            e.outputFormatting = [.sortedKeys]
            return (try? e.encode(self)) ?? Data()
        }
    }

    /// A tile of the member's view: a device, or a collection of devices,
    /// each D as the app's devices list holds it.
    public enum Tile<D: Decodable & Sendable>: Decodable, Sendable {
        case device(D)
        case collection(id: String, name: String, devices: [D])

        private enum Keys: String, CodingKey { case device, collection }
        private struct Coll: Decodable {
            var id: String
            var name: String
            var devices: [D]?
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: Keys.self)
            if let d = try c.decodeIfPresent(D.self, forKey: .device) {
                self = .device(d)
            } else {
                let col = try c.decode(Coll.self, forKey: .collection)
                self = .collection(id: col.id, name: col.name, devices: col.devices ?? [])
            }
        }
    }

    /// The member's answer to view and arrange.
    public struct View<D: Decodable & Sendable>: Decodable, Sendable {
        public var tiles: [Tile<D>]
        /// How many other devices are online, out of how many.
        public var online: Int
        public var others: Int
        /// The user changed the order, which `reset` undoes.
        public var custom: Bool

        private enum Keys: String, CodingKey { case tiles, online, others, custom }

        public init(tiles: [Tile<D>] = [], online: Int = 0, others: Int = 0, custom: Bool = false) {
            (self.tiles, self.online, self.others, self.custom) = (tiles, online, others, custom)
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: Keys.self)
            tiles = try c.decodeIfPresent([Tile<D>].self, forKey: .tiles) ?? []
            online = try c.decodeIfPresent(Int.self, forKey: .online) ?? 0
            others = try c.decodeIfPresent(Int.self, forKey: .others) ?? 0
            custom = try c.decodeIfPresent(Bool.self, forKey: .custom) ?? false
        }

        /// Every device of the tiles, in their order.
        public var devices: [D] {
            tiles.flatMap { t -> [D] in
                switch t {
                case .device(let d): [d]
                case .collection(_, _, let ds): ds
                }
            }
        }
    }
}
