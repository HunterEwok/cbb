// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Restoring a group on a new phone with the group's recovery key, scanned
 * from the QR code of its sheet (docs/protocol.md, section 10, "The
 * recovery key"). The recovery key issues this phone a member certificate
 * under its own admin CA; a computer of the group takes it on a connection
 * that carries records only and sends the group's first root in its hello.
 * The phone checks the records, then claims the group for a new root of its
 * own; the claim waits the group's delay, unless the root cancels it, and
 * [PhoneGroup.finishTakeOver] then makes the phone the root. The recovery
 * key is not kept: the claim is the one thing it signs.
 */
class Restore private constructor(
    /** The recovery key as a signer. */
    private val signer: CertificateSigner,
    /** The recovery key's admin CA, DER, from the QR code or the YubiKey's slot. */
    val adminCA: ByteArray,
    /** The key hash of the admin CA's key, which the records name in their state. */
    private val admin: ByteArray,
    /** The group's tag from the sheet's QR code; null from a YubiKey. */
    private val groupTag: String?,
    memberKey: ByteArray,
    now: Instant,
) {
    /**
     * Restores with the recovery key from the sheet's QR code. memberKey is
     * this phone's member key, a SubjectPublicKeyInfo; the key itself stays
     * in the Keystore.
     */
    constructor(key: Core.RecoveredKey, memberKey: ByteArray, now: Instant) :
        this(signer(key), key.cert ?: throw Failure(Kind.NEEDS_QR, NEEDS_QR), checked(key), key.group, memberKey, now)

    class Failure(val kind: Kind, message: String) : Exception(message)

    enum class Kind {
        /** The key was typed: a new phone needs the QR code, which carries the key's admin CA. */
        NEEDS_QR,

        /** The computer is of another group than the sheet. */
        OTHER_GROUP,

        /** The group has no recovery key now, or another one: the root removed or replaced this one. */
        NOT_THE_KEY,

        /** The computer's answer or certificate does not fit the group's records. */
        NOT_A_MEMBER,
    }

    /** This phone's new device ID. */
    val device: String = SyncEngine.newID()

    /** This phone's member certificate, from the recovery key's admin CA. */
    val memberCert: ByteArray = GroupCertificates.member(device, memberKey, adminCA, signer, now)

    /** The chain this phone presents in TLS, leaf first. */
    val chain: List<ByteArray> get() = listOf(memberCert, adminCA)

    /**
     * Checks what a computer of the group sent (fetched), and returns the
     * group as this phone holds it before its claim: a member whose
     * certificate the recovery key issued, its records and roots. The
     * group's first root must carry the sheet's tag, the records must name
     * the recovery key in their state and lead to a root that issued its
     * admin CA, and the computer's certificate must verify to a root on the
     * path and name a device the records list.
     */
    fun group(fetched: Fetched, now: Instant): PhoneGroup {
        val groupCA = fetched.groupCA ?: throw Failure(Kind.NOT_A_MEMBER, "the computer did not send the group's first root")
        val tag = GroupCertificates.tag(groupCA)
        if (groupTag != null && groupTag != tag) throw Failure(Kind.OTHER_GROUP, "the computer is of another group than the sheet")
        try {
            GroupCertificates.checkRoot(groupCA)
        } catch (e: GroupCertificates.VerifyException) {
            throw Failure(Kind.NOT_A_MEMBER, "the group's first root is not a root: ${e.message}")
        }
        val g = PhoneGroup(device, groupCA, memberCert)
        g.isRoot = false
        g.memberIssuer = adminCA
        g.adminCA = adminCA
        g.records.addAll(fetched.records, groupCA)
        g.adoptRoots()
        if (g.records.recovery?.contentEquals(admin) != true || g.records.isRevoked(admin)) {
            throw Failure(Kind.NOT_THE_KEY, NOT_THE_KEY)
        }
        if (g.trusted.none { root -> runCatching { GroupCertificates.checkAdminCA(adminCA, root) }.isSuccess }) {
            throw Failure(Kind.NOT_THE_KEY, "no root of the group issued the recovery key's admin CA")
        }
        val peer = try {
            GroupCertificates.verifyMember(fetched.peerChain, g.trusted, now)
        } catch (e: Exception) {
            throw Failure(Kind.NOT_A_MEMBER, "the computer's certificate is not from the group: ${e.message}")
        }
        if (g.devices.none { it.id == peer } || g.records.verdict(fetched.peerChain) != RecordSet.Verdict.Ok) {
            throw Failure(Kind.NOT_A_MEMBER, "the records do not list the computer")
        }
        return g
    }

    /**
     * Claims group, which [group] returned, for newRoot, a root CA for a
     * new key of this phone, with the recovery key: the record to send.
     * with is the recovery key again, as a YubiKey held to the phone a
     * second time gives it.
     */
    fun claim(group: PhoneGroup, newRoot: ByteArray, now: Instant, with: CertificateSigner = signer): Member.Record {
        if (!with.publicKeyDER.contentEquals(signer.publicKeyDER)) throw Failure(Kind.NOT_THE_KEY, "this is another key than the one that issued this phone's certificate")
        return group.claimWithRecovery(with, newRoot, now)
    }

    /** What a computer sent on a records-only connection. */
    class Fetched(
        /** The group's first root, DER, from the computer's hello. */
        val groupCA: ByteArray?,
        val records: List<Member.Record>,
        /** The computer's certificate chain from the TLS handshake. */
        val peerChain: List<ByteArray>,
    )

    companion object {
        const val NEEDS_QR = "scan the QR code of the recovery sheet: on a new phone the typed key is not enough"
        const val NOT_THE_KEY = "this is not the group's recovery key now: the root removed it or made a new one"

        /** How long the computer stays quiet before the exchange counts as done; it closes after 5 s. */
        const val QUIET_MS = 2_000L

        /**
         * Exchanges records with a computer on a connection that carries
         * records only (docs/protocol.md, section 10, "Records only"): this
         * phone's hello without a digest, so the computer sends all its
         * records; then send, once the computer's hello came; then whatever
         * arrives until it is quiet for quietMS. It closes t.
         */
        fun exchange(
            t: FrameTransport,
            name: String,
            os: String,
            now: Instant,
            send: List<Member.Record> = emptyList(),
            quietMS: Long = QUIET_MS,
        ): Fetched {
            val inbox = LinkedBlockingQueue<Any>()
            val reader = Thread {
                try {
                    while (true) {
                        val (n, binary) = Member.header(t.read(4))
                        val body = t.read(n)
                        if (!binary) inbox.put(Member.decode(body))
                    }
                } catch (e: Exception) {
                    inbox.put(e)
                }
            }
            reader.isDaemon = true
            try {
                t.write(Member.encode(Member.Message.Hello(Member.Role.PHONE, Member.Hello(now.toEpochMilli(), name = name, os = os))))
                reader.start()
                var groupCA: ByteArray? = null
                var hello = false
                val records = mutableListOf<Member.Record>()
                while (true) {
                    val m = inbox.poll(if (hello) quietMS else TLSTransport.HANDSHAKE_TIMEOUT_MS.toLong(), TimeUnit.MILLISECONDS)
                    when {
                        m == null && !hello -> throw Failure(Kind.NOT_A_MEMBER, "the computer sent no hello")
                        m == null -> break
                        m is Exception && !hello -> throw Failure(Kind.NOT_A_MEMBER, "the computer closed the connection: ${m.message}")
                        m is Exception -> break
                        !hello -> {
                            val h = m as? Member.Message.Hello ?: throw Failure(Kind.NOT_A_MEMBER, "the computer did not start with a hello")
                            hello = true
                            groupCA = h.hello.groupCA
                            for (chunk in Member.Record.chunks(send)) t.write(Member.encode(Member.Message.Records(chunk)))
                        }
                        m is Member.Message.Records -> if (records.size + m.records.size <= MAX_RECORDS) records += m.records
                    }
                }
                return Fetched(groupCA, records, t.peerChain)
            } finally {
                t.close()
            }
        }

        /** The most records one exchange takes: the core's set keeps no more. */
        private const val MAX_RECORDS = 4096

        /**
         * Restores with the recovery key on a YubiKey: signer is the key in
         * the slot whose certificate, adminCA, is the key's admin CA
         * ([Piv.recoveryKeys]). The card signs this phone's member
         * certificate here and, held again, the claim.
         */
        fun onCard(signer: CertificateSigner, adminCA: ByteArray, memberKey: ByteArray, now: Instant): Restore {
            val info = try {
                CertificateInfo(adminCA)
            } catch (e: Exception) {
                throw Failure(Kind.NOT_THE_KEY, "the YubiKey's certificate does not parse")
            }
            if (!info.publicKey.contentEquals(signer.publicKeyDER)) throw Failure(Kind.NOT_THE_KEY, "the YubiKey's certificate is for another key")
            return Restore(signer, adminCA, Records.keyHashOfCert(adminCA), null, memberKey, now)
        }

        private fun checked(key: Core.RecoveredKey): ByteArray {
            val ca = key.cert ?: throw Failure(Kind.NEEDS_QR, NEEDS_QR)
            if (!Records.keyHashOfCert(ca).contentEquals(key.admin)) throw Failure(Kind.NEEDS_QR, "the sheet's admin CA is for another key")
            return key.admin
        }

        private fun signer(key: Core.RecoveredKey): CertificateSigner {
            val spki = p256SPKI(key.public) ?: throw Failure(Kind.NEEDS_QR, "the recovery key is not a P-256 key")
            val pub = p256PublicKey(spki) ?: throw Failure(Kind.NEEDS_QR, "the recovery key is not a P-256 key")
            val priv = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(key.pkcs8))
            return SoftwareSigner(KeyPair(pub, priv))
        }
    }
}
