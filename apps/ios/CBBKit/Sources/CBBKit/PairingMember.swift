// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// A connection that carries pairing frames: a TLS connection in the app,
/// anything in tests.
public protocol FrameTransport: AnyObject {
    func write(_ data: Data) async throws
    /// Reads exactly n bytes, or throws.
    func read(exactly n: Int) async throws -> Data
    /// The peer's certificate chain from the TLS handshake, DER, leaf
    /// first: the leaf, then its admin CA when one issued it; empty for a
    /// transport without TLS.
    var peerChain: [Data] { get }
}

public extension FrameTransport {
    var peerChain: [Data] { [] }
}

extension FrameTransport {
    func writeFrame(_ f: Pairing.Frame) async throws { try await write(Pairing.encode(f)) }

    func readFrame() async throws -> Pairing.Frame {
        let n = try Pairing.length(header: try await read(exactly: 4))
        return try Pairing.decode(body: try await read(exactly: n))
    }
}

/// The admitting side of pairing, which the phone, as the root of the
/// group, plays: it dials a listening computer and confirms the code first
/// (docs/protocol.md, section 6, "The joiner listens"), or, as the group's
/// hub, takes a device that dialed it with a remote invitation (section
/// 12), which confirms first.
public enum PairingMember {
    /// A device that proved it knows an invitation's secret, for the admin
    /// to confirm.
    public struct Request: Equatable {
        public var device: String
        public var info: Pairing.Info
        public var fingerprint: String
    }

    /// A remote invitation's side of the exchange: its secret in place of
    /// the code, and confirm, which asks the admin whether to admit the
    /// device (up to 5 minutes, docs/protocol.md, section 12) once it
    /// proved that it knows the secret, and before the certificate is made.
    public struct Invitation: Sendable {
        public var secret: Data
        public var confirm: @Sendable (Request) async -> Bool

        public init(secret: Data, confirm: @escaping @Sendable (Request) async -> Bool) {
            (self.secret, self.confirm) = (secret, confirm)
        }
    }

    public struct Admitted: Equatable {
        public var device: String
        public var info: Pairing.Info
        public var cert: Data
        /// Whether the computer said it stored its identity. Without it, it
        /// may still hold the certificate.
        public var confirmed: Bool
    }

    public enum Failure: Error, Equatable {
        /// The computer's answer: a wrong code, or another refusal.
        case refused(Pairing.ErrorCode)
        case badJoiner(String)
        case protocolError(String)
    }

    /// Runs the exchange over a connection the member dialed and whose TLS
    /// handshake is done: memberCert and joinerCert are the two
    /// certificates of the handshake, the joiner's already checked against
    /// the QR code's fingerprint; sessionID is the TLS exporter's output.
    /// issue makes the welcome for the joiner's device ID, public key and
    /// description; it is called only after the joiner proved it knows the
    /// code. With invitation, the device dialed this phone: code is unused,
    /// the device confirms the secret first, and the admin confirms the
    /// device.
    public static func admit(over t: FrameTransport, code: String, memberCert: Data, joinerCert: Data,
                             sessionID: [UInt8], memberAD: Pairing.MemberAD, taken: (String) -> Bool = { _ in false },
                             invitation: Invitation? = nil,
                             issue: (String, Data, Pairing.Info) throws -> Pairing.Welcome) async throws -> Admitted {
        let joiner = try CertificateInfo(der: joinerCert)
        guard let device = joiner.commonName, GroupCertificates.isDeviceID(device) else {
            throw Failure.badJoiner("the computer's certificate names no device ID")
        }
        // As a computer admits one (docs/protocol.md, section 6): a single
        // certificate with a P-256 key, the key the welcome certifies.
        guard t.peerChain.count <= 1 else { throw Failure.badJoiner("the joining device must send exactly one certificate") }
        guard P256.Signing.PublicKey(spki: joiner.publicKey) != nil else {
            throw Failure.badJoiner("the joining device's key is not a P-256 key")
        }
        let first = try await t.readFrame()
        // A device picks its own ID, so one that is in the group already is
        // refused before the exchange.
        if taken(device) {
            try? await t.writeFrame(Pairing.Frame(error: Pairing.ErrorCode.taken.rawValue))
            throw Failure.refused(.taken)
        }
        guard let ya = first.msg, let ada = first.ad,
              let info = try? JSONDecoder().decode(Pairing.Info.self, from: ada), info.isValid else {
            throw Failure.protocolError("bad first frame")
        }
        let adb = try JSONEncoder().encode(memberAD)
        var st = try CPace(role: .responder, password: invitation.map { Array($0.secret) } ?? Array(code.utf8),
                           channelID: Pairing.channelID(memberCert: memberCert, joinerCert: joinerCert),
                           sessionID: sessionID, ad: Array(adb))
        _ = try st.finish(peerMessage: Array(ya), peerAD: Array(ada))
        // Invited, the device confirms first: this side shows nothing of the
        // secret to a device that does not know it.
        try await t.writeFrame(Pairing.Frame(msg: Data(st.message), ad: adb, tag: invitation == nil ? Data(st.confirmationTag!) : nil))
        let confirm = try await t.readFrame()
        if let code = confirm.error { throw Failure.refused(Pairing.ErrorCode(wire: code)) }
        guard let tag = confirm.tag, (try? st.verify(peerTag: Array(tag))) != nil else {
            try? await t.writeFrame(Pairing.Frame(error: Pairing.ErrorCode.wrongCode.rawValue))
            throw Failure.refused(.wrongCode)
        }
        if let invitation,
           !(await invitation.confirm(Request(device: device, info: info, fingerprint: Pairing.fingerprint(cert: joinerCert)))) {
            try? await t.writeFrame(Pairing.Frame(error: Pairing.ErrorCode.declined.rawValue))
            throw Failure.refused(.declined)
        }
        let welcome = try issue(device, joiner.publicKey, info)
        try await t.writeFrame(Pairing.Frame(tag: invitation == nil ? nil : Data(st.confirmationTag!), welcome: welcome))
        // The welcome went out: the computer counts as admitted now.
        let done = try? await t.readFrame()
        return Admitted(device: device, info: info, cert: welcome.cert, confirmed: done?.ok == true)
    }
}
