// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// The joining side of pairing, which a phone plays to join a group. To
/// join a phone group it listens and shows its QR code, and an admin phone
/// dials it and confirms the code first (docs/protocol.md, section 6, "The
/// joiner listens"): a wrong code never spends it, so the joiner may take
/// another attempt. To join a computer's group it dials the window that
/// `cbb pair` opened on the group's root and confirms the code first ("A
/// phone joins a computer's group"): once it sent its confirmation the code
/// is spent, whatever happens next.
public enum PairingJoiner {
    /// What a successful exchange gives: this phone's device ID and the
    /// welcome, checked.
    public struct Joined: Equatable {
        public var device: String
        public var welcome: Pairing.Welcome
        /// The admitting phone and the group it announced.
        public var member: Pairing.MemberAD
    }

    public enum Failure: Error, Equatable {
        /// The other device's answer, or a wrong code it showed.
        case refused(Pairing.ErrorCode)
        case badWelcome(String)
        case protocolError(String)
    }

    /// A failure after this phone sent its confirmation to a computer's
    /// window: the code is spent and may not be tried again, at this
    /// address or another. underlying is what failed.
    public struct Spent: Error {
        public var underlying: any Error
    }

    /// Runs the exchange over a connection the admitting phone dialed and
    /// whose TLS handshake is done: joinerCert is this phone's self-signed
    /// certificate, which the QR code names, memberCert the admitting
    /// phone's leaf, and sessionID the TLS exporter's output. info carries
    /// this phone's name, os "ios" and its admin key. store saves the
    /// checked result; the other phone hears whether that worked.
    public static func accept(over t: FrameTransport, code: String, info: Pairing.Info, memberCert: Data, joinerCert: Data,
                              sessionID: [UInt8], now: Date, store: (Joined) throws -> Void) async throws -> Joined {
        try await exchange(over: t, code: code, info: info, memberCert: memberCert, joinerCert: joinerCert,
                           sessionID: sessionID, now: now, memberFirst: true, store: store)
    }

    /// Runs the exchange over a connection this phone dialed to a
    /// computer's pairing window, whose TLS handshake is done: joinerCert
    /// is this phone's self-signed certificate, which it showed in the
    /// handshake, memberCert the computer's leaf, and sessionID the TLS
    /// exporter's output. This phone confirms the code first, so what fails
    /// after that comes as Spent. info carries this phone's name, its OS and
    /// its admin key, for which the group's root sends an admin CA. store
    /// saves the checked result; the computer hears whether that worked.
    public static func join(over t: FrameTransport, code: String, info: Pairing.Info, memberCert: Data, joinerCert: Data,
                            sessionID: [UInt8], now: Date, store: (Joined) throws -> Void) async throws -> Joined {
        try await exchange(over: t, code: code, info: info, memberCert: memberCert, joinerCert: joinerCert,
                           sessionID: sessionID, now: now, memberFirst: false, store: store)
    }

    /// The frames of the exchange (section 6, "Frames"). With memberFirst
    /// the member sends its confirmation with its key, before this phone
    /// sends its own; otherwise this phone confirms first and the member's
    /// confirmation comes with the welcome.
    private static func exchange(over t: FrameTransport, code: String, info: Pairing.Info, memberCert: Data, joinerCert: Data,
                                 sessionID: [UInt8], now: Date, memberFirst: Bool,
                                 store: (Joined) throws -> Void) async throws -> Joined {
        guard let device = try CertificateInfo(der: joinerCert).commonName, GroupCertificates.isDeviceID(device) else {
            throw Failure.protocolError("this phone's certificate names no device ID")
        }
        let ada = try JSONEncoder().encode(info)
        var st = try CPace(role: .initiator, password: Array(code.utf8),
                           channelID: Pairing.channelID(memberCert: memberCert, joinerCert: joinerCert),
                           sessionID: sessionID, ad: Array(ada))
        try await t.writeFrame(Pairing.Frame(msg: Data(st.message), ad: ada))
        let reply = try await t.readFrame()
        if let code = reply.error { throw Failure.refused(Pairing.ErrorCode(wire: code)) }
        guard let yb = reply.msg, let adb = reply.ad, !memberFirst || reply.tag != nil,
              let member = try? JSONDecoder().decode(Pairing.MemberAD.self, from: adb) else {
            throw Failure.protocolError("bad second frame")
        }
        _ = try st.finish(peerMessage: Array(yb), peerAD: Array(adb))
        if memberFirst, (try? st.verify(peerTag: Array(reply.tag!))) == nil {
            try? await t.writeFrame(Pairing.Frame(error: Pairing.ErrorCode.wrongCode.rawValue))
            throw Failure.refused(.wrongCode)
        }
        // From here on a member that did not confirm first can check a
        // guess of the code.
        do {
            try await t.writeFrame(Pairing.Frame(tag: Data(st.confirmationTag!)))
            let final = try await t.readFrame()
            if let code = final.error { throw Failure.refused(Pairing.ErrorCode(wire: code)) }
            if !memberFirst {
                guard let tb = final.tag, (try? st.verify(peerTag: Array(tb))) != nil else {
                    throw Failure.protocolError("the computer did not prove that it knows the code")
                }
            }
            guard let welcome = final.welcome else { throw Failure.protocolError("no welcome") }
            let joined = Joined(device: device, welcome: welcome, member: member)
            do {
                try check(joined, info: info, memberCert: memberCert, joinerCert: joinerCert, now: now)
                try store(joined)
            } catch {
                try? await t.writeFrame(Pairing.Frame(error: Pairing.ErrorCode.refused.rawValue))
                throw error
            }
            // Stored; the other device admitted this one when it sent the
            // welcome, whether or not it hears this.
            try? await t.writeFrame(Pairing.Frame(ok: true))
            return joined
        } catch {
            throw memberFirst ? error : Spent(underlying: error)
        }
    }

    /// Checks a welcome as Go's joiner does (section 6, "Welcome"), for a
    /// phone: the group CA is a phone's root and the one announced; the
    /// admitting phone's certificate is from one of the group's roots or
    /// from the issuer and names that phone; this phone's certificate is
    /// for its device and key; no CA keys; an admin CA, when present, is for
    /// the admin key this phone sent, under the current root; the roots are
    /// the ones the welcome's records lead to.
    static func check(_ j: Joined, info: Pairing.Info, memberCert: Data, joinerCert: Data, now: Date) throws {
        let w = j.welcome
        guard GroupCertificates.tag(groupCA: w.groupCA) == j.member.group else {
            throw Failure.badWelcome("the other phone sent another group CA than it announced")
        }
        guard (try? ParsedCertificate(der: w.groupCA))?.pathLength == 1 else {
            throw Failure.badWelcome("the group CA is not a phone's root")
        }
        let later = w.roots ?? []
        guard later.allSatisfy({ (try? GroupCertificates.checkRoot($0)) != nil }) else {
            throw Failure.badWelcome("a later root is not a phone's root")
        }
        // The roots are only those the records lead to: an admin could
        // otherwise name a root of its own, and every certificate from it
        // would pass here for good, whatever the group's root removes.
        var path = RecordSet()
        path.addAll(w.records ?? [], groupCA: w.groupCA)
        path.takeClaimTimes(w.claimTimes ?? [])
        guard path.roots == later else {
            throw Failure.badWelcome("the other phone's roots are not the ones the group's records lead to")
        }
        let trusted = [w.groupCA] + later
        if let issuer = w.issuer, !trusted.contains(where: { (try? GroupCertificates.checkAdminCA(issuer, root: $0)) != nil }) {
            throw Failure.badWelcome("the other phone's issuer is not an admin CA of the group")
        }
        let issuerChain = w.issuer.map { [$0] } ?? []
        let theirs = try? GroupCertificates.verifyMember(chain: [memberCert] + issuerChain, roots: trusted, now: now)
        guard theirs == j.member.device else {
            throw Failure.badWelcome("the other phone's certificate is not from the group or does not name it")
        }
        guard (try? GroupCertificates.verifyMember(chain: [w.cert] + issuerChain, roots: trusted, now: now)) == j.device,
              try CertificateInfo(der: w.cert).publicKey == CertificateInfo(der: joinerCert).publicKey else {
            throw Failure.badWelcome("the certificate is not for this phone")
        }
        if let adminCA = w.adminCA {
            guard let key = info.adminKey, (try? GroupCertificates.checkAdminCA(adminCA, root: trusted.last!)) != nil,
                  let ca = try? CertificateInfo(der: adminCA), ca.publicKey == key,
                  ca.commonName == "cbb admin " + j.device else {
                throw Failure.badWelcome("the admin CA is not for this phone's admin key")
            }
        }
    }
}
