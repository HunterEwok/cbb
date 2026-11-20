// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// A JSON value of a vectors file kept as its JSON text, for the release
/// files the vectors hold as objects: the kit passes a file's bytes to the
/// core as they came, and these are the bytes the tests pass.
struct RawFile: Decodable {
    let data: Data

    init(from decoder: Decoder) throws {
        data = try JSONSerialization.data(withJSONObject: Self.value(decoder), options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private struct Any_: Decodable {
        let value: Any
        init(from decoder: Decoder) throws { value = try RawFile.value(decoder) }
    }

    fileprivate static func value(_ decoder: Decoder) throws -> Any {
        let c = try decoder.singleValueContainer()
        if let o = try? c.decode([String: Any_].self) { return o.mapValues(\.value) }
        if let a = try? c.decode([Any_].self) { return a.map(\.value) }
        if let i = try? c.decode(Int64.self) { return i }
        if let b = try? c.decode(Bool.self) { return b }
        if let s = try? c.decode(String.self) { return s }
        if c.decodeNil() { return NSNull() }
        return try c.decode(Double.self)
    }
}
