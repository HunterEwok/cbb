// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

/**
 * The admitting side of pairing, which the phone, as an admin of the
 * group, plays: it dials a listening device and confirms the code first
 * (docs/protocol.md, section 6, "The joiner listens"), or, as the group's
 * hub, takes a device that dialed it with a remote invitation (section
 * 12), which confirms first.
 */
object PairingMember {
    data class Admitted(
        val device: String,
        val info: Pairing.Info,
        val cert: ByteArray,
        /** Whether the device said it stored its identity. Without it, it may still hold the certificate. */
        val confirmed: Boolean,
    )

    /** Why admitting failed: the device's answer (a wrong code, or another refusal), a bad joiner, or a broken exchange. */
    class Failure(message: String, val code: Pairing.ErrorCode? = null) : Exception(message)

    /** A device that proved it knows an invitation's secret, for the admin to confirm. */
    data class Request(val device: String, val info: Pairing.Info, val fingerprint: String)

    /**
     * A remote invitation's side of the exchange: its secret in place of the
     * code, and confirm, which asks the admin whether to admit the device
     * (up to 5 minutes, docs/protocol.md, section 12) once it proved that it
     * knows the secret, and before the certificate is made.
     */
    class Invitation(val secret: ByteArray, val confirm: (Request) -> Boolean)

    /**
     * Runs the exchange over a connection the member dialed and whose TLS
     * handshake is done: memberCert and joinerCert are the two certificates
     * of the handshake, the joiner's already checked against the QR code's
     * fingerprint; sessionID is the TLS exporter's output. issue makes the
     * welcome for the joiner's device ID, public key and description; it is
     * called only after the joiner proved it knows the code. taken reports
     * whether the joiner's device ID is in the group already, which every
     * caller must answer; such a joiner is refused before the exchange, as a
     * device picks its own ID. With
     * invitation, the device dialed this phone: code is unused, the device
     * confirms the secret first, and the admin confirms the device.
     */
    fun admit(
        t: FrameTransport,
        code: String,
        memberCert: ByteArray,
        joinerCert: ByteArray,
        sessionID: ByteArray,
        memberAD: Pairing.MemberAD,
        taken: (String) -> Boolean,
        invitation: Invitation? = null,
        issue: (String, ByteArray, Pairing.Info) -> Pairing.Welcome,
    ): Admitted {
        val joiner = CertificateInfo(joinerCert)
        val device = joiner.commonName
        if (device == null || !GroupCertificates.isDeviceID(device)) throw Failure("the device's certificate names no device ID")
        // As a computer admits one (docs/protocol.md, section 6): a single
        // certificate with a P-256 key, the key the welcome certifies.
        if (t.peerChain.size > 1) throw Failure("the joining device must send exactly one certificate")
        if (p256PublicKey(joiner.publicKey) == null) throw Failure("the joining device's key is not a P-256 key")
        val first = t.readFrame()
        if (taken(device)) {
            runCatching { t.writeFrame(Pairing.Frame(error = Pairing.ErrorCode.TAKEN.wire)) }
            throw Failure("a device with this device ID is in the group already", Pairing.ErrorCode.TAKEN)
        }
        val ya = first.msg
        val ada = first.ad
        val info = ada?.let { Pairing.Info.decode(it) }
        if (ya == null || ada == null || info == null || !info.isValid) throw Failure("bad first frame")
        val adb = memberAD.encode()
        val password = invitation?.secret ?: code.toByteArray()
        val st = CPace(CPace.Role.RESPONDER, password, Pairing.channelID(memberCert, joinerCert), sessionID, adb)
        st.finish(ya, ada)
        // Invited, the device confirms first: this side shows nothing of
        // the secret to a device that does not know it.
        t.writeFrame(Pairing.Frame(msg = st.message, ad = adb, tag = if (invitation == null) st.confirmationTag else null))
        val confirm = t.readFrame()
        confirm.error?.let { throw Failure("refused: $it", Pairing.ErrorCode.of(it)) }
        val tag = confirm.tag
        if (tag == null || runCatching { st.verify(tag) }.isFailure) {
            runCatching { t.writeFrame(Pairing.Frame(error = Pairing.ErrorCode.WRONG_CODE.wire)) }
            throw Failure("wrong code", Pairing.ErrorCode.WRONG_CODE)
        }
        // A phone proves it holds the admin key it offers, on this
        // connection, before any admin CA is made for it.
        if (info.adminKey != null && !info.provesAdminKey(sessionID)) {
            runCatching { t.writeFrame(Pairing.Frame(error = Pairing.ErrorCode.REFUSED.wire)) }
            throw Failure("the phone did not prove that it holds its admin key", Pairing.ErrorCode.REFUSED)
        }
        if (invitation != null && !invitation.confirm(Request(device, info, Pairing.fingerprint(joinerCert)))) {
            runCatching { t.writeFrame(Pairing.Frame(error = Pairing.ErrorCode.DECLINED.wire)) }
            throw Failure("the admin did not confirm the device", Pairing.ErrorCode.DECLINED)
        }
        val welcome = issue(device, joiner.publicKey, info)
        t.writeFrame(Pairing.Frame(welcome = welcome, tag = if (invitation == null) null else st.confirmationTag))
        // The welcome went out: the device counts as admitted now.
        val done = runCatching { t.readFrame() }.getOrNull()
        return Admitted(device, info, welcome.cert, done?.ok == true)
    }
}
