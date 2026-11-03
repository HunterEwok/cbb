// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// The arrangement of the device tiles (docs/apps.md, "Collections and the
/// order of the tiles"): the user's own order and collections, kept in the
/// app's settings and never sent to the group. The twin of the tray app's
/// arrange.go and the Android kit's Arrangement.kt, all three checked
/// against testdata/arrangement/vectors.json.
public struct Arrangement: Codable, Equatable, Sendable {
    public static let version = 1
    public static let maxCollections = 32
    public static let maxName = 64 // bytes

    /// A device, or a collection of devices.
    public enum Item: Codable, Equatable, Sendable {
        case device(String)
        case collection(Collection)

        private enum Keys: String, CodingKey { case device, collection }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: Keys.self)
            if let d = try c.decodeIfPresent(String.self, forKey: .device) {
                self = .device(d)
            } else {
                self = .collection(try c.decode(Collection.self, forKey: .collection))
            }
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: Keys.self)
            switch self {
            case .device(let d): try c.encode(d, forKey: .device)
            case .collection(let col): try c.encode(col, forKey: .collection)
            }
        }
    }

    /// A named collection of devices, one level only.
    public struct Collection: Codable, Equatable, Sendable {
        public var id: String
        public var name: String
        public var devices: [String]

        public init(id: String, name: String, devices: [String]) {
            self.id = id
            self.name = name
            self.devices = devices
        }

        private enum Keys: String, CodingKey { case id, name, devices }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: Keys.self)
            id = try c.decode(String.self, forKey: .id)
            name = try c.decode(String.self, forKey: .name)
            devices = try c.decodeIfPresent([String].self, forKey: .devices) ?? []
        }
    }

    /// A device or a collection, as an operation names it.
    public enum Ref: Equatable, Sendable {
        case device(String)
        case collection(String)
    }

    /// A change the user makes; see apply.
    public enum Op: Equatable, Sendable {
        case move(Ref, before: Ref?)
        case into(device: String, collection: String)
        case out(device: String)
        case new(name: String, devices: [String])
        case rename(collection: String, name: String)
        case ungroup(collection: String)
        case reset
    }

    /// An operation that does not fit the arrangement.
    public struct Refused: Error, Equatable {
        public var reason: String
    }

    public var v: Int
    public var group: String
    public private(set) var items: [Item]

    /// A fresh arrangement for the group.
    public init(group: String) {
        v = Arrangement.version
        self.group = group
        items = []
    }

    private enum Keys: String, CodingKey { case v, group, items }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        v = try c.decode(Int.self, forKey: .v)
        group = try c.decode(String.self, forKey: .group)
        items = try c.decodeIfPresent([Item].self, forKey: .items) ?? []
    }

    /// The stored arrangement for the group, from its JSON: a fresh one when
    /// there is none, it does not parse, or it was made for another group or
    /// by another version.
    public static func decode(_ data: Data?, group: String) -> Arrangement {
        guard let data, let a = try? JSONDecoder().decode(Arrangement.self, from: data),
              a.v == version, a.group == group else { return Arrangement(group: group) }
        return a
    }

    /// The arrangement as JSON, for the settings.
    public func encoded() -> Data {
        (try? JSONEncoder().encode(self)) ?? Data()
    }

    /// What the app shows: the stored items in order without the devices
    /// that are not listed, collections without listed devices left out
    /// unless they were just made, then the listed devices that appear
    /// nowhere, in the order given. self, this device, is never among them:
    /// the app shows it first.
    public func view(devices: [String], self me: String?) -> [Item] {
        let listed = Set(devices.filter { $0 != me })
        var seen = Set<String>()
        var out: [Item] = []
        for it in items {
            switch it {
            case .device(let d):
                if listed.contains(d), seen.insert(d).inserted { out.append(it) }
            case .collection(var c):
                let had = c.devices.isEmpty
                c.devices = c.devices.filter { listed.contains($0) && seen.insert($0).inserted }
                if !c.devices.isEmpty || had { out.append(.collection(c)) }
            }
        }
        for d in devices where listed.contains(d) && seen.insert(d).inserted {
            out.append(.device(d))
        }
        return out
    }

    /// Drops the devices that are not listed, and the collections that lose
    /// their last device that way; the app calls it only when the list is
    /// whole (the group loaded, this device in it).
    public mutating func prune(devices: [String]) {
        let listed = Set(devices)
        items = items.compactMap { it in
            switch it {
            case .device(let d):
                return listed.contains(d) ? it : nil
            case .collection(var c):
                let had = c.devices.isEmpty
                c.devices = c.devices.filter(listed.contains)
                return had || !c.devices.isEmpty ? .collection(c) : nil
            }
        }
    }

    /// Makes the change, on the arrangement as view shows it for devices
    /// (self left out); the stored items then hold the whole order. move puts
    /// an item before another, or at the end of its level (a device in a
    /// collection: the end of the collection); a device before a device in a
    /// collection joins it, a collection never goes into one. into appends a
    /// device to a collection, out puts it after its collection, new makes a
    /// collection where its first device was, ungroup puts the devices back
    /// where it was, and reset brings back the order given with the
    /// collections kept. A change that does not fit throws Refused and
    /// leaves the arrangement as it was.
    public mutating func apply(_ op: Op, devices: [String], self me: String?) throws {
        var w = Work(items: items)
        var shown = Set<String>()
        for it in view(devices: devices, self: me) {
            switch it {
            case .device(let d): shown.insert(d)
            case .collection(let c): shown.formUnion(c.devices)
            }
        }
        for d in devices where d != me && shown.contains(d) && w.find(d) == nil {
            w.items.append(.device(d))
        }
        try w.apply(op, devices: devices, shown: shown)
        items = w.items
    }

    private struct Work {
        var items: [Item]

        static let refused = Refused(reason: "the arrangement cannot take that")

        func find(_ d: String) -> Int? {
            items.firstIndex {
                switch $0 {
                case .device(let x): return x == d
                case .collection(let c): return c.devices.contains(d)
                }
            }
        }

        func collection(_ id: String) -> Int? {
            items.firstIndex {
                if case .collection(let c) = $0 { return c.id == id }
                return false
            }
        }

        func coll(_ i: Int) -> Collection {
            guard case .collection(let c) = items[i] else { preconditionFailure("not a collection") }
            return c
        }

        /// Removes d from where it is; a collection it leaves empty goes away.
        mutating func take(_ d: String, keep: String? = nil) {
            items = items.compactMap { it in
                switch it {
                case .device(let x):
                    return x == d ? nil : it
                case .collection(var c):
                    guard c.id != keep, c.devices.contains(d) else { return it }
                    c.devices.removeAll { $0 == d }
                    return c.devices.isEmpty ? nil : .collection(c)
                }
            }
        }

        func newID() -> String {
            var n = 1
            while collection("c\(n)") != nil { n += 1 }
            return "c\(n)"
        }

        mutating func apply(_ op: Op, devices: [String], shown: Set<String>) throws {
            switch op {
            case .move(let item, let before):
                try move(item, before: before, shown: shown)
            case .into(let d, let id):
                guard shown.contains(d), let ci = collection(id) else { throw Work.refused }
                if coll(ci).devices.contains(d) { return }
                take(d)
                let i = collection(id)!
                var c = coll(i)
                c.devices.append(d)
                items[i] = .collection(c)
            case .out(let d):
                guard shown.contains(d), let ci = find(d), case .collection(let c) = items[ci] else { throw Work.refused }
                take(d)
                items.insert(.device(d), at: collection(c.id).map { $0 + 1 } ?? ci)
            case .new(let name, let ds):
                let name = try Arrangement.collectionName(name)
                let n = items.filter { if case .collection = $0 { return true }; return false }.count
                guard n < Arrangement.maxCollections else {
                    throw Refused(reason: "at most \(Arrangement.maxCollections) collections")
                }
                var picked: [String] = []
                for d in ds {
                    guard shown.contains(d), !picked.contains(d) else { throw Work.refused }
                    picked.append(d)
                }
                let at = picked.first.flatMap(find) ?? items.count
                let c = Collection(id: newID(), name: name, devices: picked)
                items.insert(.collection(c), at: at)
                for d in picked { take(d, keep: c.id) }
            case .rename(let id, let name):
                guard let ci = collection(id) else { throw Work.refused }
                var c = coll(ci)
                c.name = try Arrangement.collectionName(name)
                items[ci] = .collection(c)
            case .ungroup(let id):
                guard let ci = collection(id) else { throw Work.refused }
                items.replaceSubrange(ci...ci, with: coll(ci).devices.map { Item.device($0) })
            case .reset:
                reset(devices)
            }
        }

        mutating func move(_ item: Ref, before: Ref?, shown: Set<String>) throws {
            switch item {
            case .device(let d):
                guard shown.contains(d), let di = find(d) else { throw Work.refused }
                if before == .device(d) { return }
                var src: Collection?
                if case .collection(let c) = items[di] { src = c }
                switch before {
                case nil:
                    take(d)
                    if let src, let ci = collection(src.id) {
                        var c = coll(ci)
                        c.devices.append(d)
                        items[ci] = .collection(c)
                    } else {
                        items.append(.device(d))
                    }
                case .collection(let id)?:
                    guard var at = collection(id) else { throw Work.refused }
                    take(d)
                    // The collection may have gone with its last device:
                    // then the device stands where it was.
                    if let ci = collection(id) { at = ci }
                    items.insert(.device(d), at: at)
                case .device(let b)?:
                    guard shown.contains(b), find(b) != nil else { throw Work.refused }
                    take(d)
                    let bi = find(b)!
                    if case .collection(var c) = items[bi] {
                        c.devices.insert(d, at: c.devices.firstIndex(of: b)!)
                        items[bi] = .collection(c)
                    } else {
                        items.insert(.device(d), at: bi)
                    }
                }
            case .collection(let id):
                guard let ci = collection(id) else { throw Work.refused }
                if before == .collection(id) { return }
                switch before {
                case .collection(let b)?:
                    guard collection(b) != nil else { throw Work.refused }
                case .device(let b)?:
                    guard shown.contains(b), find(b) != nil else { throw Work.refused }
                case nil:
                    break
                }
                let it = items.remove(at: ci)
                switch before {
                case nil: items.append(it)
                case .collection(let b)?: items.insert(it, at: collection(b)!)
                case .device(let b)?: items.insert(it, at: find(b)!)
                }
            }
        }

        mutating func reset(_ devices: [String]) {
            var rank: [String: Int] = [:]
            for (i, d) in devices.enumerated() where rank[d] == nil { rank[d] = i }
            func less(_ x: String, _ y: String) -> Bool {
                switch (rank[x], rank[y]) {
                case let (rx?, ry?): return rx < ry
                case (_?, nil): return true
                case (nil, _?): return false
                case (nil, nil): return x < y
                }
            }
            items = items.map {
                guard case .collection(var c) = $0 else { return $0 }
                c.devices = stableSorted(c.devices, by: less)
                return .collection(c)
            }
            func first(_ it: Item) -> String? {
                switch it {
                case .device(let d): return d
                case .collection(let c): return c.devices.first
                }
            }
            items = stableSorted(items) { x, y in
                switch (first(x), first(y)) {
                case let (fx?, fy?): return less(fx, fy)
                case (_?, nil): return true
                default: return false
                }
            }
        }

        func stableSorted<T>(_ a: [T], by less: (T, T) -> Bool) -> [T] {
            a.enumerated().sorted { x, y in
                if less(x.element, y.element) { return true }
                if less(y.element, x.element) { return false }
                return x.offset < y.offset
            }.map(\.element)
        }
    }

    /// A collection's name trimmed, 1 to 64 bytes.
    public static func collectionName(_ s: String) throws -> String {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, t.utf8.count <= maxName else {
            throw Refused(reason: "a collection's name has 1 to \(maxName) bytes")
        }
        return t
    }
}
