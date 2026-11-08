// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CBBKit
import Foundation
import os
import Photos
import UniformTypeIdentifiers

private let log = Logger(subsystem: "tools.cbb", category: "gallery")

/// Puts a received image or video in Photos, as the Android and Aurora apps
/// put it in their gallery: one image or video file that the button saves,
/// and the image it fetches for the clipboard. The app asks only to add to
/// the library (NSPhotoLibraryAddUsageDescription), never to read it; with
/// that access iOS lets an app neither find nor make an album, so the item
/// lands in Recents.
enum Gallery {
    /// What Photos keeps.
    enum Kind: Equatable {
        case image, video

        var resource: PHAssetResourceType { self == .image ? .photo : .video }
    }

    /// The kind of a file by its name's extension; nil for any other file.
    static func kind(path: String) -> Kind? {
        let ext = (path as NSString).pathExtension
        guard !ext.isEmpty, let t = UTType(filenameExtension: ext) else { return nil }
        return kind(t)
    }

    /// The kind of a clipboard part by its media type.
    static func kind(type: String) -> Kind? {
        UTType(mimeType: type).flatMap(kind)
    }

    private static func kind(_ t: UTType) -> Kind? {
        if t.conforms(to: .image) { return .image }
        if t.conforms(to: .movie) { return .video }
        return nil
    }

    /// The kind of a copy of files that Photos takes: exactly one file, at
    /// the top, an image or a video.
    static func kind(of m: Media.Manifest) -> Kind? {
        guard m.parts.count == 1, let p = m.parts.first, !p.dir, let path = p.path, !path.contains("/") else { return nil }
        return kind(path: path)
    }

    /// Whether the app may add to Photos, asking the user the first time.
    static func allowed() async -> Bool {
        switch PHPhotoLibrary.authorizationStatus(for: .addOnly) {
        case .authorized, .limited: return true
        case .notDetermined:
            let s = await PHPhotoLibrary.requestAuthorization(for: .addOnly)
            return s == .authorized || s == .limited
        default: return false
        }
    }

    /// Adds the file at url to Photos under the name it came with; the file
    /// stays where it is.
    static func add(_ url: URL, kind: Kind, name: String) async throws {
        try await PHPhotoLibrary.shared().performChanges {
            let o = PHAssetResourceCreationOptions()
            o.originalFilename = name
            PHAssetCreationRequest.forAsset().addResource(with: kind.resource, fileURL: url, options: o)
        }
    }

    /// Keeps an image the button fetched for the clipboard in Photos too,
    /// when the user allows it; a failure only goes to the log.
    static func keep(_ data: Data, type: String) async {
        guard kind(type: type) == .image, await allowed() else { return }
        do {
            try await PHPhotoLibrary.shared().performChanges {
                let o = PHAssetResourceCreationOptions()
                if let ext = UTType(mimeType: type)?.preferredFilenameExtension { o.originalFilename = "CBB.\(ext)" }
                PHAssetCreationRequest.forAsset().addResource(with: .photo, data: data, options: o)
            }
        } catch {
            log.error("keeping the image in Photos: \(String(reflecting: error), privacy: .public)")
        }
    }

    /// Adds the one image or video of a copy of files to Photos; false when
    /// it is not one, the user did not allow it, or Photos refused it, so
    /// that the caller saves it in Received instead.
    static func add(_ parts: [CoreMember.Fetched], of m: Media.Manifest) async -> Bool {
        guard let kind = kind(of: m), let p = parts.first(where: { !$0.dir }), let path = p.path, await allowed() else { return false }
        do {
            try await add(URL(fileURLWithPath: p.file), kind: kind, name: path)
            return true
        } catch {
            log.error("adding \(kind == .image ? "an image" : "a video", privacy: .public) to Photos: \(String(reflecting: error), privacy: .public)")
            return false
        }
    }
}
