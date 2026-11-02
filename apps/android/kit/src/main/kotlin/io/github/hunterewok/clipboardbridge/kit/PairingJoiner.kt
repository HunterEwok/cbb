// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import java.time.Instant

/**
 * The joining side of pairing, which a phone plays to join a group. To
 * join a phone group it listens and shows its QR code, and an admin phone
 * dials it and confirms the code first (docs/protocol.md, section 6, "The
 * joiner listens"): a wrong code never spends it, so the joiner may take
 * another attempt. To join a computer's group it dials the window that
 * `cbb pair` opened on the group's root and confirms the code first ("A
 * phone joins a computer's group"): once it sent its confirmation the code
 * is spent, whatever happens next.
 */
object PairingJoiner {
    /** What a successful exchange gives: this phone's device ID and the welcome, checked. */
    class Joined(
        val device: String,
        val welcome: Pairing.Welcome,
        /** The admitting phone and the group it announced. */
        val member: Pairing.MemberAD,
    )

    /**
     * Why joining failed: the other device's answer (or a wrong code it
     * showed), a bad welcome, or a broken exchange. spent reports that this
     * phone had sent its confirmation, so the code may not be tried again,
     * at this address or another.
     */
    class Failure(message: String, val code: Pairing.ErrorCode? = null, val spent: Boolean = false) : Exception(message)

    /**
     * Runs the exchange over a connection the admitting phone dialed and
     * whose TLS handshake is done: joinerCert is this phone's self-signed
     * certificate, which the QR code names, memberCert the admitting phone's
     * leaf, and sessionID the TLS exporter's output. info carries this
     * phone's name, its OS and its admin key. store saves the checked
     * result; the other phone hears whether that worked.
     */
    fun accept(
        t: FrameTransport,
        code: String,
        info: Pairing.Info,
        memberCert: ByteArray,
        joinerCert: ByteArray,
        sessionID: ByteArray,
        now: Instant,
        store: (Joined) -> Unit,
    ): Joined = exchange(t, code, info, memberCert, joinerCert, sessionID, now, memberFirst = true, store)

    /**
     * Runs the exchange over a connection this phone dialed to a computer's
     * pairing window, whose TLS handshake is done: joinerCert is this
     * phone's self-signed certificate, which it showed in the handshake,
     * memberCert the computer's leaf, and sessionID the TLS exporter's
     * output. This phone confirms the code first, so a Failure after that
     * is spent. info carries this phone's name, its OS and its admin key,
     * for which the group's root sends an admin CA. store saves the checked
     * result; the computer hears whether that worked.
     */
    fun join(
        t: FrameTransport,
        code: String,
        info: Pairing.Info,
        memberCert: ByteArray,
        joinerCert: ByteArray,
        sessionID: ByteArray,
        now: Instant,
        store: (Joined) -> Unit,
    ): Joined = exchange(t, code, info, memberCert, joinerCert, sessionID, now, memberFirst = false, store)

    /**
     * The frames of the exchange (section 6, "Frames"). With memberFirst
     * the member sends its confirmation with its key, before this phone
     * sends its own; otherwise this phone confirms first and the member's
     * confirmation comes with the welcome.
     */
    private fun exchange(
        t: FrameTransport,
        code: String,
        info: Pairing.Info,
        memberCert: ByteArray,
        joinerCert: ByteArray,
        sessionID: ByteArray,
        now: Instant,
        memberFirst: Boolean,
        store: (Joined) -> Unit,
    ): Joined {
        val device = CertificateInfo(joinerCert).commonName
        if (device == null || !GroupCertificates.isDeviceID(device)) throw Failure("this phone's certificate names no device ID")
        val ada = info.encode()
        val st = CPace(CPace.Role.INITIATOR, code.toByteArray(), Pairing.channelID(memberCert, joinerCert), sessionID, ada)
        t.writeFrame(Pairing.Frame(msg = st.message, ad = ada))
        val reply = t.readFrame()
        reply.error?.let { throw Failure("refused: $it", Pairing.ErrorCode.of(it)) }
        val yb = reply.msg
        val adb = reply.ad
        val member = adb?.let { Pairing.MemberAD.decode(it) }
        if (yb == null || adb == null || member == null || memberFirst && reply.tag == null) throw Failure("bad second frame")
        st.finish(yb, adb)
        if (memberFirst && runCatching { st.verify(reply.tag!!) }.isFailure) {
            runCatching { t.writeFrame(Pairing.Frame(error = Pairing.ErrorCode.WRONG_CODE.wire)) }
            throw Failure("wrong code", Pairing.ErrorCode.WRONG_CODE)
        }
        // From here on a member that did not confirm first can check a guess of the code.
        val spent = !memberFirst
        try {
            t.writeFrame(Pairing.Frame(tag = st.confirmationTag))
            val final = t.readFrame()
            final.error?.let { throw Failure("refused: $it", Pairing.ErrorCode.of(it), spent) }
            if (!memberFirst && (final.tag == null || runCatching { st.verify(final.tag) }.isFailure)) {
                throw Failure("the computer did not prove that it knows the code", spent = spent)
            }
            val welcome = final.welcome ?: throw Failure("no welcome", spent = spent)
            val joined = Joined(device, welcome, member)
            try {
                check(joined, info, memberCert, joinerCert, now)
                store(joined)
            } catch (e: Exception) {
                runCatching { t.writeFrame(Pairing.Frame(error = Pairing.ErrorCode.REFUSED.wire)) }
                throw e
            }
            // Stored; the other device admitted this one when it sent the
            // welcome, whether or not it hears this.
            runCatching { t.writeFrame(Pairing.Frame(ok = true)) }
            return joined
        } catch (e: Failure) {
            throw if (spent && !e.spent) Failure(e.message ?: "joining failed", e.code, spent = true) else e
        } catch (e: Exception) {
            throw if (spent) Failure(e.message ?: e.toString(), spent = true).apply { initCause(e) } else e
        }
    }

    /**
     * Checks a welcome as Go's joiner does (section 6, "Welcome"), for a
     * phone: the group CA is a phone's root and the one announced; the
     * admitting phone's certificate is from one of the group's roots or from
     * the issuer and names that phone; this phone's certificate is for its
     * device and key; no CA keys; an admin CA, when present, is for the
     * admin key this phone sent, under the current root; the roots are the
     * ones the welcome's records lead to.
     */
    internal fun check(j: Joined, info: Pairing.Info, memberCert: ByteArray, joinerCert: ByteArray, now: Instant) {
        val w = j.welcome
        if (GroupCertificates.tag(w.groupCA) != j.member.group) throw Failure("the other phone sent another group CA than it announced")
        if (runCatching { ParsedCertificate(w.groupCA).pathLength }.getOrNull() != 1) throw Failure("the group CA is not a phone's root")
        val later = w.roots.orEmpty()
        if (!later.all { runCatching { GroupCertificates.checkRoot(it) }.isSuccess }) throw Failure("a later root is not a phone's root")
        // The roots are only those the records lead to: an admin could otherwise name a root of its own, and
        // every certificate from it would pass here for good, whatever the group's root removes.
        val path = RecordSet().apply {
            addAll(w.records.orEmpty(), w.groupCA)
            takeClaimTimes(w.claimTimes.orEmpty())
        }.roots
        if (path.size != later.size || path.zip(later).any { (a, b) -> !a.contentEquals(b) }) {
            throw Failure("the other phone's roots are not the ones the group's records lead to")
        }
        val trusted = listOf(w.groupCA) + later
        val issuer = w.issuer
        if (issuer != null && trusted.none { runCatching { GroupCertificates.checkAdminCA(issuer, it) }.isSuccess }) {
            throw Failure("the other phone's issuer is not an admin CA of the group")
        }
        val issuerChain = listOfNotNull(issuer)
        val theirs = runCatching { GroupCertificates.verifyMember(listOf(memberCert) + issuerChain, trusted, now) }.getOrNull()
        if (theirs != j.member.device) throw Failure("the other phone's certificate is not from the group or does not name it")
        val mine = runCatching { GroupCertificates.verifyMember(listOf(w.cert) + issuerChain, trusted, now) }.getOrNull()
        if (mine != j.device || !CertificateInfo(w.cert).publicKey.contentEquals(CertificateInfo(joinerCert).publicKey)) {
            throw Failure("the certificate is not for this phone")
        }
        val adminCA = w.adminCA
        if (adminCA != null) {
            val key = info.adminKey
            val ca = runCatching { CertificateInfo(adminCA) }.getOrNull()
            if (key == null || runCatching { GroupCertificates.checkAdminCA(adminCA, trusted.last()) }.isFailure || ca == null ||
                !ca.publicKey.contentEquals(key) || ca.commonName != "clipboardbridge admin ${j.device}"
            ) {
                throw Failure("the admin CA is not for this phone's admin key")
            }
        }
    }
}
