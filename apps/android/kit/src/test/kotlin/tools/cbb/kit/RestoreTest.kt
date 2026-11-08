// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import java.time.Instant
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
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
    /** When the group was made. */
    private val t0 = Instant.now().minusSeconds(3600)

    private val top: File = createTempDirectory("cbb-restore").toFile()
    private val members = mutableListOf<CoreMember>()

    @AfterTest
    fun cleanUp() {
        members.forEach { it.close() }
        top.deleteRecursively()
    }

    /** The new phone's member in the Rust core, as the app starts it once [Restore.group] gave it the group. */
    private fun member(r: Restore, group: PhoneGroup, key: SoftwareSigner): CoreMember {
        val m = CoreMember.start(
            CoreMember.Start(File(top, "${members.size}").apply { mkdirs() }, "New", "android", "17", "0.6.0", device = r.device, publicKey = key.publicKeyDER,
                seal = CoreGroup.SEAL, cert = r.memberCert, issuer = r.adminCA, groupCA = group.groupCA, roots = group.trusted),
            key::signDigest,
        ) { }
        members += m
        m.addRecords(group.records.records)
        return m
    }

    private class Group(t0: Instant) {
        val rootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0, "Lost")
        val computer = RootTest.Computer(root.groupCA, rootKey, t0)
        val recovery: PhoneGroup.Recovery

        init {
            root.records.clock = { t0 }
            root.record(computer.device, "one", "full", computer.keyHash, rootKey, t0)
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
            pc.write(Member.encode(Member.Message.Hello(Member.Role.FULL, Member.Hello(0, name = "one", os = "linux", groupCA = groupCA))))
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
        assertFalse(group.isRoot)
        assertEquals(g.root.tag, group.tag)
        assertTrue(group.devices.none { it.id == r.device }, "no record names the new phone yet")
        assertIs<RecordSet.Verdict.NotListed>(group.records.verdict(r.chain), "the computers take its chain for records only")

        val m = member(r, group, memberKey)
        val newRootKey = SoftwareSigner()
        val newRoot = m.rootCA(newRootKey.publicKeyDER, newRootKey::signDigest)
        r.claim(group, m, newRoot)
        group.add(m.records())
        assertEquals("pending", group.claimState)
        val finish = { m.finishTakeover(newRoot, newRootKey.publicKeyDER, "New", "android", Records.HARDWARE, null, newRootKey::signDigest) }
        assertEquals("pending", finish().state, "the claim waits")

        // Once the delay ran out (the root set none here), the phone is the root.
        val none = g.root.setTakeoverDelay(0, g.rootKey, Instant.now())
        group.add(listOf(none))
        m.addRecords(listOf(none))
        val done = finish()
        assertEquals("effective", done.state)
        group.becameRoot(done.cert!!, m.records())
        assertTrue(group.isRoot)
        assertNull(group.memberIssuer)
        assertNull(group.adminCA)
        assertEquals(r.device, group.records.rootDevice)
        assertEquals(listOf("New", "one"), group.devices.map { it.name }.sorted(), "the lost root's device goes")
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
        val memberKey = SoftwareSigner()
        val r = Restore.onCard(Piv.Signer(card, s, CertificateInfo(cert).publicKey, "123456"), cert, memberKey.publicKeyDER, t0)
        val (phone, pc) = computer(g.root.records.records, g.root.groupCA, listOf(g.computer.cert))
        val fetched = Restore.exchange(phone, "New", "android", t0, quietMS = 300)
        pc.join()
        val group = r.group(fetched, t0)
        val m = member(r, group, memberKey)
        val newRootKey = SoftwareSigner()
        val newRoot = m.rootCA(newRootKey.publicKeyDER, newRootKey::signDigest)
        assertEquals(Restore.Kind.NOT_THE_KEY, assertFailsWith<Restore.Failure> { r.claim(group, m, newRoot, SoftwareSigner()) }.kind)
        Piv.select(card)
        r.claim(group, m, newRoot, Piv.Signer(card, s, CertificateInfo(cert).publicKey, "123456"))
        group.add(m.records())
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
