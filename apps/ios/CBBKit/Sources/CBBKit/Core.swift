// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CCbbCore
import Foundation

/// The Rust core's one entry point (docs/core-api.md), the group's rules
/// that every member shares: JSON bytes in, JSON bytes out, through the C
/// functions of ffi/ (ffi/include/cbb_core.h). The kit asks the
/// core instead of writing the rules again in Swift.
public enum Core {
    /// The version of the request and answer shapes the kit speaks; `call`
    /// refuses a core of another.
    public static let abi = 1

    /// An error answer of the core: a stable code and name, a short message
    /// for the user and the causes under it. The app shows `message`, and
    /// `details` under it in debug mode; the log always gets both.
    public struct Refusal: Error, Equatable, Decodable, CustomStringConvertible {
        public var code: Int
        public var name: String
        public var message: String
        public var details: String?

        public var description: String {
            guard let details, !details.isEmpty else { return "core: \(message) (\(name), code \(code))" }
            return "core: \(message) (\(name), code \(code)): \(details)"
        }
    }

    /// A linked core that speaks another ABI, or an answer the kit cannot
    /// read: a build that put the wrong library in.
    public struct Mismatch: Error, Equatable, CustomStringConvertible {
        public var reason: String
        public var description: String { "core: \(reason)" }
    }

    /// The core's answer to the operation `version`.
    public struct Version: Decodable, Equatable {
        public var abi: Int
        public var core: String
        public var source: String?

        /// How `cbb version` names the core, for the apps' about screens and
        /// error reports.
        public var line: String { "core \(core), abi \(abi), source \(source ?? "unknown")" }
    }

    /// Sends one request and returns the core's answer, after checking that
    /// the core speaks `abi`. A refusal of the request is an answer with an
    /// error, not an error of `call`.
    public static func call(_ request: Data) throws -> Data {
        let got = Int(cbb_abi())
        guard got == abi else { throw Mismatch(reason: "the linked core speaks ABI \(got), not \(abi)") }
        var count = 0
        let answer: UnsafeMutablePointer<UInt8>? = request.withUnsafeBytes { raw in
            cbb_call(raw.bindMemory(to: UInt8.self).baseAddress, raw.count, &count)
        }
        guard let answer else { throw Mismatch(reason: "the core gave no answer") }
        defer { cbb_free(answer, count) }
        return Data(bytes: answer, count: count)
    }

    private struct Request<A: Encodable>: Encodable {
        var abi: Int
        var op: String
        var args: A?
    }

    private struct Answer<R: Decodable>: Decodable {
        var ok: R?
        var error: Refusal?
    }

    private struct None: Codable {}

    /// Sends the operation `op` with `args` and decodes the answer's `ok`;
    /// a refusal comes back as a `Refusal`.
    public static func run<A: Encodable, R: Decodable>(_ op: String, _ args: A?, as _: R.Type = R.self) throws -> R {
        let answer = try call(JSONEncoder().encode(Request(abi: abi, op: op, args: args)))
        let a: Answer<R>
        do {
            a = try JSONDecoder().decode(Answer<R>.self, from: answer)
        } catch {
            throw Mismatch(reason: "the answer to \(op) does not read: \(error)")
        }
        if let e = a.error { throw e }
        guard let ok = a.ok else { throw Mismatch(reason: "the answer to \(op) has neither ok nor error") }
        return ok
    }

    /// Sends the operation `op`, which takes no arguments.
    public static func run<R: Decodable>(_ op: String, as _: R.Type = R.self) throws -> R {
        try run(op, Optional<None>.none, as: R.self)
    }

    /// The linked core's version, ABI and the commit it was built from.
    public static func version() throws -> Version { try run("version") }

    /// Checks a signed body that is not a record through the core's
    /// parse_body (docs/core-api.md, "Signed bodies"): `kind` is
    /// `command`, `credential`, `keys`, `release`, `channel` or
    /// `attest-status`. The core alone decides whether the body is taken;
    /// a body it refuses throws its Refusal.
    static func checkBody(_ kind: String, _ body: Data) throws {
        struct Args: Encodable { var kind: String, body: Data }
        struct Answer: Decodable {}
        _ = try run("parse_body", Args(kind: kind, body: body), as: Answer.self)
    }

    /// A command in the open with its orders sealed to key, the
    /// receiver's key for sealed messages (seal_command, docs/core-api.md,
    /// "Signed bodies"), for the sender to sign.
    static func sealCommand(_ body: Data, key: Data) throws -> Data {
        struct Args: Encodable { var body: Data, key: Data }
        struct Answer: Decodable { var body: Data }
        return try run("seal_command", Args(body: body, key: key), as: Answer.self).body
    }

    /// The public key for sealed messages of secret, 32 random bytes the
    /// device keeps: the `seal` its pairing and device record carry.
    public static func sealPublic(_ secret: Data) throws -> Data {
        struct Args: Encodable { var secret: Data }
        struct Answer: Decodable { var key: Data }
        return try run("seal_public", Args(secret: secret), as: Answer.self).key
    }

    /// A recovery sheet (docs/protocol.md, section 10, "The recovery
    /// key"): the QR code's text, the key in groups of four, and the key
    /// hash the `recovery` record names.
    public struct RecoverySheet: Decodable, Equatable, Sendable {
        public var qr: String
        public var text: String
        public var admin: Data
    }

    /// The recovery sheet for key (its 32 bytes), its admin CA and the
    /// group's tag.
    public static func recoverySheet(key: Data, cert: Data, group: String) throws -> RecoverySheet {
        struct Args: Encodable { var key: Data, cert: Data, group: String }
        return try run("recovery_sheet", Args(key: key, cert: cert, group: group), as: RecoverySheet.self)
    }

    /// A recovery key read from a sheet: cert and group only from its QR
    /// code.
    public struct RecoveredKey: Decodable, Equatable, Sendable {
        /// The private key's 32 bytes.
        public var key: Data
        public var pkcs8: Data
        /// The public key, uncompressed.
        public var `public`: Data
        /// Its key hash, as the `recovery` record names it.
        public var admin: Data
        public var cert: Data?
        public var group: String?
    }

    /// What read_recovery_sheet says of a text: the key, or why it is not
    /// one, with a reason (not_sheet, damaged, check, key, cert, mismatch,
    /// group) and a sentence for the user.
    public enum SheetReading: Equatable, Sendable {
        case key(RecoveredKey)
        case refused(reason: String, message: String)
    }

    /// Reads what the user scanned or typed from a recovery sheet.
    public static func readRecoverySheet(_ text: String) throws -> SheetReading {
        struct Args: Encodable { var text: String }
        struct Refused: Decodable { var reason: String, message: String }
        struct Answer: Decodable { var sheet: RecoveredKey?, refused: Refused? }
        let a = try run("read_recovery_sheet", Args(text: text), as: Answer.self)
        if let s = a.sheet { return .key(s) }
        guard let r = a.refused else { throw Mismatch(reason: "the answer to read_recovery_sheet has neither sheet nor refused") }
        return .refused(reason: r.reason, message: r.message)
    }

    /// checkBody, with a refusal in words for the log: the core's message
    /// and its details.
    static func bodyRefusal(_ kind: String, _ body: Data) -> String? {
        do {
            try checkBody(kind, body)
            return nil
        } catch let r as Refusal {
            guard let d = r.details, !d.isEmpty else { return r.message }
            return "\(r.message): \(d)"
        } catch {
            return "\(error)"
        }
    }
}
