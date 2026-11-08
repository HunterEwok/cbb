// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CBBKit
import CryptoKit
import Foundation
import UIKit
import UniformTypeIdentifiers

/// Images between the iPhone's clipboard and the group (docs/design.md,
/// "Images and files"): the button sends an image copied on the phone as
/// PNG or JPEG, HEIC turned into JPEG, and puts one a computer copied on
/// the clipboard of this phone only, after fetching it whole.
enum Images {
    /// The largest image the phone fetches or sends, as the computers'
    /// default limit at home.
    static let maxCopy: Int64 = 100 << 20

    static let types = ["image/gif", "image/png", "image/jpeg"]

    /// The uniform types of the image types the group carries.
    static let utis: [(UTType, String)] = [(.gif, "image/gif"), (.png, "image/png"), (.jpeg, "image/jpeg")]

    /// The image part of a media event, GIF before PNG before JPEG, or nil for files
    /// and other data.
    static func part(of m: Media.Manifest?) -> Media.Part? {
        guard let m, !m.isFiles else { return nil }
        for t in types {
            if let p = m.parts.first(where: { $0.type == t && $0.sha256 != nil }) { return p }
        }
        return nil
    }

    /// What the button compares for an image: its hash, which no text
    /// equals.
    static func key(_ sha256: Data) -> String { "\u{0}image:" + sha256.map { String(format: "%02x", $0) }.joined() }

    /// An image the phone copied, as the group carries it.
    struct Copied {
        var type: String
        var data: Data
        var key: String { Images.key(Data(SHA256.hash(data: data))) }
    }

    /// The image on the pasteboard as GIF, PNG or JPEG: HEIC and other
    /// formats become JPEG, or PNG when they have transparency. nil when
    /// there is none, or it is too large.
    static func read(_ pb: UIPasteboard) -> Copied? {
        guard pb.hasImages else { return nil }
        var copied: Copied?
        for (uti, type) in utis where copied == nil {
            if let d = pb.data(forPasteboardType: uti.identifier) { copied = Copied(type: type, data: d) }
        }
        if copied == nil, let image = pb.image { copied = convert(image) }
        return copied.flatMap { Int64($0.data.count) <= maxCopy ? $0 : nil }
    }

    /// An image of another format as JPEG, or PNG when it has an alpha
    /// channel the JPEG would lose.
    static func convert(_ image: UIImage) -> Copied? {
        let alpha: Bool
        switch image.cgImage?.alphaInfo {
        case .none?, .noneSkipFirst?, .noneSkipLast?, nil: alpha = false
        default: alpha = true
        }
        if alpha { return image.pngData().map { Copied(type: "image/png", data: $0) } }
        return image.jpegData(compressionQuality: 0.9).map { Copied(type: "image/jpeg", data: $0) }
    }

    /// The image an item provider of Share holds, as GIF, PNG or JPEG,
    /// like read; nil when it holds none, or it is too large.
    static func load(_ p: NSItemProvider) async -> Copied? {
        for (uti, type) in utis where p.hasItemConformingToTypeIdentifier(uti.identifier) {
            if let d = await data(p, uti), Int64(d.count) <= maxCopy { return Copied(type: type, data: d) }
        }
        guard p.hasItemConformingToTypeIdentifier(UTType.image.identifier), let d = await data(p, .image), let image = UIImage(data: d) else { return nil }
        return convert(image).flatMap { Int64($0.data.count) <= maxCopy ? $0 : nil }
    }

    /// The bytes of an item provider in type.
    static func data(_ p: NSItemProvider, _ type: UTType) async -> Data? {
        await withCheckedContinuation { c in
            _ = p.loadDataRepresentation(for: type) { d, _ in c.resume(returning: d) }
        }
    }

    /// Puts a received image on this phone's clipboard, with alt, its
    /// plain-text alternative, next to it; local only, so Universal
    /// Clipboard does not carry it back to a Mac of the group.
    static func write(_ data: Data, type: String, alt: String) {
        let uti = (utis.first { $0.1 == type }?.0 ?? .jpeg).identifier
        var item: [String: Any] = [uti: data]
        if !alt.isEmpty { item[UTType.plainText.identifier] = alt }
        UIPasteboard.general.setItems([item], options: [.localOnly: true])
    }
}
