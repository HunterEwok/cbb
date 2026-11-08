// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Restoring a group on a new phone with the recovery key
 * (docs/protocol.md, section 10, "The recovery key"): the root phone is
 * lost, and a new phone scans the sheet, takes the records from a computer
 * of the group and claims the group.
 */
class RestoreTest {
    /** When the group was made: long enough ago that a claim made then took effect by now. */
    private val t0 = Instant.now().minusSeconds(100L * 3600)

    private class Group(t0: Instant) {
        val rootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0, "Lost")
        val computer = RootTest.Computer(root.groupCA, rootKey, t0)
        val recovery: PhoneGroup.Recovery

        init {
            root.records.clock = { t0 }
            root.record(computer.device, "one", "member", computer.keyHash, rootKey, t0, caps = Records.CAPS)
            recovery = root.makeRecovery(rootKey, t0)
        }

        val sheet: Core.RecoveredKey get() = assertIs<Core.SheetReading.Key>(Core.readRecoverySheet(recovery.sheet.qr)).key
    }

    /**
     * Plays the computer's side of a records-only connection, as Go's
     * node does with a device no record names: its hello with groupCA,
     * then its records, then whatever arrives until the phone closes.
     */
    private fun computer(records: List<Member.Record>, groupCA: ByteArray?, chain: List<ByteArray>): Pair<Pipe, Background<List<Member.Record>>> {
        val (phone, pc) = Pipe.pair()
        phone.peerChain = chain
        val got = Background<List<Member.Record>> {
            pc.write(Member.encode(Member.Message.Hello(Member.Role.MEMBER, Member.Hello(0, name = "one", os = "linux", groupCA = groupCA))))
            val first = Member.decode(pc.read(Member.header(pc.read(4)).first))
            assertIs<Member.Message.Hello>(first)
            assertNull(first.hello.records, "the phone holds no records yet")
            for (c in Member.Record.chunks(records)) pc.write(Member.encode(Member.Message.Records(c)))
            val in_ = mutableListOf<Member.Record>()
            try {
                while (true) {
                    val m = Member.decode(pc.read(Member.header(pc.read(4)).first))
                    if (m is Member.Message.Records) in_ += m.records
                }
            } catch (e: java.io.IOException) {
                // the phone closed
            }
            in_
        }
        return phone to got
    }

    @Test
    fun restores() {
        val g = Group(t0)
        val memberKey = SoftwareSigner()
        val r = Restore(g.sheet, memberKey.publicKeyDER, t0)
        assertContentEquals(g.recovery.adminCA, r.chain[1])
        assertContentEquals(r.memberCert, r.chain[0])

        val (phone, pc) = computer(g.root.records.records, g.root.groupCA, listOf(g.computer.cert))
        val fetched = Restore.exchange(phone, "New", "android", t0, quietMS = 300)
        pc.join()
        val group = r.group(fetched, t0)
        group.records.clock = { t0 }
        assertFalse(group.isRoot)
        assertEquals(g.root.tag, group.tag)
        assertTrue(group.devices.none { it.id == r.device }, "no record names the new phone yet")
        assertIs<RecordSet.Verdict.NotListed>(group.records.verdict(r.chain), "the computers take its chain for records only")

        val newRootKey = SoftwareSigner()
        val newRoot = GroupCertificates.groupCA(newRootKey, t0, pathLength = 1)
        val claim = r.claim(group, newRoot, t0)
        assertEquals("pending", group.claimState)
        assertTrue(group.finishTakeOver(newRootKey, t0).isEmpty(), "the claim waits")

        // The claim reaches the computer on the next exchange.
        val (phone2, pc2) = computer(g.root.records.records, g.root.groupCA, listOf(g.computer.cert))
        Restore.exchange(phone2, "New", "android", t0, send = listOf(claim), quietMS = 300)
        assertEquals(listOf(Records.id(claim).toHex()), pc2.join().map { Records.id(it).toHex() })

        // Once the delay ran out, the phone is the root.
        group.records.clock = { Instant.now() }
        val rs = group.finishTakeOver(newRootKey, Instant.now(), "New", seal = null)
        assertTrue(group.isRoot)
        assertNull(group.memberIssuer)
        assertNull(group.adminCA)
        assertEquals(r.device, group.records.rootDevice)
        assertEquals(listOf("New", "one"), group.devices.map { it.name }.sorted(), "the lost root's device goes")
        assertTrue(rs.isNotEmpty())
        assertEquals(r.device, GroupCertificates.verifyMember(group.memberChain, listOf(newRoot), Instant.now()))
        assertContentEquals(CertificateInfo(r.memberCert).publicKey, CertificateInfo(group.memberCert).publicKey, "the same member key")
        assertNull(group.records.refused(group.memberChain))
    }

    /** The same with the recovery key on a YubiKey: the card signs the member certificate, then, held again, the claim. */
    @Test
    fun restoresWithCard() {
        val g = Group(t0)
        val card = FakePivCard()
        Piv.select(card)
        Piv.verify(card, "123456")
        Piv.authenticate(card)
        val slot = Piv.freeSlot(card)
        val (ca, _) = g.root.makeRecoveryOnCard(Piv.generate(card, slot), g.rootKey, t0)
        Piv.putCertificate(card, slot, ca)

        Piv.select(card)
        val (s, cert) = Piv.recoveryKeys(card).single()
        val r = Restore.onCard(Piv.Signer(card, s, CertificateInfo(cert).publicKey, "123456"), cert, SoftwareSigner().publicKeyDER, t0)
        val (phone, pc) = computer(g.root.records.records, g.root.groupCA, listOf(g.computer.cert))
        val fetched = Restore.exchange(phone, "New", "android", t0, quietMS = 300)
        pc.join()
        val group = r.group(fetched, t0)
        group.records.clock = { t0 }
        val newRoot = GroupCertificates.groupCA(SoftwareSigner(), t0, pathLength = 1)
        assertEquals(Restore.Kind.NOT_THE_KEY, assertFailsWith<Restore.Failure> { r.claim(group, newRoot, t0, SoftwareSigner()) }.kind)
        Piv.select(card)
        r.claim(group, newRoot, t0, Piv.Signer(card, s, CertificateInfo(cert).publicKey, "123456"))
        assertEquals("pending", group.claimState)
        assertEquals(2, card.signed)
    }

    @Test
    fun refusesWhatDoesNotFit() {
        val g = Group(t0)
        val memberKey = SoftwareSigner().publicKeyDER

        // A typed key carries no admin CA.
        val typed = assertIs<Core.SheetReading.Key>(Core.readRecoverySheet(g.recovery.sheet.text)).key
        assertEquals(Restore.Kind.NEEDS_QR, assertFailsWith<Restore.Failure> { Restore(typed, memberKey, t0) }.kind)

        fun refused(records: List<Member.Record>, groupCA: ByteArray?, chain: List<ByteArray> = listOf(g.computer.cert), key: Core.RecoveredKey = g.sheet): Restore.Kind {
            val r = Restore(key, memberKey, t0)
            val (phone, pc) = computer(records, groupCA, chain)
            val f = Restore.exchange(phone, "New", "android", t0, quietMS = 300)
            pc.join()
            return assertFailsWith<Restore.Failure> { r.group(f, t0) }.kind
        }
        assertEquals(Restore.Kind.NOT_A_MEMBER, refused(g.root.records.records, null), "no group CA")

        val other = Group(t0)
        assertEquals(Restore.Kind.OTHER_GROUP, refused(other.root.records.records, other.root.groupCA, listOf(other.computer.cert)))

        val stranger = RootTest.Computer(other.root.groupCA, other.rootKey, t0)
        assertEquals(Restore.Kind.NOT_A_MEMBER, refused(g.root.records.records, g.root.groupCA, listOf(stranger.cert)), "a computer of another group")
        val unlisted = RootTest.Computer(g.root.groupCA, g.rootKey, t0)
        assertEquals(Restore.Kind.NOT_A_MEMBER, refused(g.root.records.records, g.root.groupCA, listOf(unlisted.cert)), "a computer the records do not list")

        // The root made a new recovery key: the old sheet no longer counts.
        val old = g.sheet
        g.root.makeRecovery(g.rootKey, t0.plusSeconds(1))
        assertEquals(Restore.Kind.NOT_THE_KEY, refused(g.root.records.records, g.root.groupCA, key = old))
    }
}
