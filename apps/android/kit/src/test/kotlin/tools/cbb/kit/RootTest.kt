// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import java.io.File
import java.time.Instant
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Handing the group over (docs/protocol.md, section 10, "Handing the group over"):
 * the root phone is lost, and admin phone B claims the group for a new
 * root through its member in the Rust core, which takes effect after the
 * delay; the tests that need it to take effect set the delay to 0.
 */
class RootTest {
    /** When the group was made, for the certificates of the computers and the stolen root key. */
    private val t0 = Instant.now().minusSeconds(3600)

    private val groups = mutableListOf<Group>()

    @AfterTest
    fun cleanUp() {
        groups.forEach { it.close() }
    }

    /** A computer: its device ID, key and member certificate. */
    class Computer(ca: ByteArray, signer: CertificateSigner, now: Instant) {
        val device = SyncEngine.newID()
        val key = SoftwareSigner()
        val cert = GroupCertificates.member(device, key.publicKeyDER, ca, signer, now)
        val keyHash: ByteArray get() = Records.keyHashOfCert(cert)
    }

    /**
     * The group before the loss: the root phone, which admitted computer one itself, and admin phone B, which
     * admitted computer two; B's member runs in the Rust core.
     */
    class Group(now: Instant) : AutoCloseable {
        val rootKey = SoftwareSigner()
        val adminKey = SoftwareSigner()
        val newRootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, now, "Lost")
        private val bDevice = SyncEngine.newID()
        private val bKey = SoftwareSigner()
        private val dir: File = createTempDirectory("cbb-root").toFile()

        /** B's admin CA, under the old root. */
        val adminCA = GroupCertificates.adminCA(bDevice, adminKey.publicKeyDER, root.groupCA, rootKey)
        private val bCert = GroupCertificates.member(bDevice, bKey.publicKeyDER, root.groupCA, rootKey, now)
        val b = PhoneGroup(bDevice, root.groupCA, bCert)
        val one = Computer(root.groupCA, rootKey, now)
        val two = Computer(adminCA, adminKey, now)
        val member: CoreMember

        init {
            root.record(bDevice, "B", "phone", Records.keyHashOfCert(bCert), rootKey, now, Records.keyHashOfCert(adminCA))
            root.record(one.device, "one", "full", one.keyHash, rootKey, now)
            b.isRoot = false
            b.adminCA = adminCA
            b.add(root.records.records)
            b.record(two.device, "two", "full", two.keyHash, adminKey, now)
            root.add(b.records.records)
            member = CoreMember.start(
                CoreMember.Start(dir, "B", "android", "17", "0.6.0", device = bDevice, publicKey = bKey.publicKeyDER,
                    seal = CoreGroup.SEAL, cert = bCert, groupCA = root.groupCA, roots = root.trusted),
                bKey::signDigest,
            ) { }
            member.addRecords(b.records.records)
        }

        /** Hands records the root signed to B and its member. */
        fun fromRoot(vararg rs: Member.Record) {
            b.add(rs.toList())
            member.addRecords(rs.toList())
        }

        /** A root CA for B's new root key, from the member. */
        fun newRoot(): ByteArray = member.rootCA(newRootKey.publicKeyDER, newRootKey::signDigest)

        /** B claims the group from the lost root phone for newRoot, as the app does. */
        fun claim(newRoot: ByteArray) {
            b.checkTakeOver(root.device)
            member.claim(CoreMember.Claim.TAKE_OVER, newRoot, adminKey.publicKeyDER, adminCA, adminKey::signDigest, root.device)
            b.claimed(newRoot, root.device)
            b.add(member.records())
        }

        /** Asks B's member to finish the claim for newRoot, and makes B the root once it did. */
        fun finish(newRoot: ByteArray): CoreMember.Takeover {
            val f = member.finishTakeover(newRoot, newRootKey.publicKeyDER, "B", "android", Records.HARDWARE, null, newRootKey::signDigest)
            if (f.state == "effective") b.becameRoot(assertNotNull(f.cert), member.records()) else b.add(member.records())
            return f
        }

        /** B's claim record, as its member signed it. */
        val claimRecord: Member.Record get() = member.records().single { Wire.parse(it.body)?.optString("type") == "claim" }

        override fun close() {
            member.close()
            dir.deleteRecursively()
        }
    }

    private fun group(now: Instant = t0): Group = Group(now).also { groups += it }

    /** B's claim, and B as the root once it took effect at once: the records the takeover added, the claim among them. */
    private fun takeOver(g: Group): List<Member.Record> {
        g.fromRoot(g.root.setTakeoverDelay(0, g.rootKey, Instant.now()))
        val before = g.b.records.records.map { Key(Records.id(it)) }.toSet()
        val newRoot = g.newRoot()
        g.claim(newRoot)
        assertEquals("effective", g.finish(newRoot).state)
        return g.b.records.records.filter { Key(Records.id(it)) !in before }
    }

    @Test
    fun takeOver() {
        val g = group()
        val lost = g.root.device
        assertEquals(lost, g.b.records.rootDevice)
        val rs = takeOver(g)
        val types = rs.map { Wire.parse(it.body)?.optString("type") }
        assertTrue("claim" in types && "device" in types && "revoke" in types, "the claim, B's own device and the removal of the lost phone: $types")
        assertTrue(g.b.isRoot)
        assertNull(g.b.adminCA)
        assertNull(g.b.claim)
        assertEquals(1, g.b.roots.size)
        assertEquals(g.b.roots.map { Key(it) }, g.b.records.roots.map { Key(it) })
        assertEquals(g.root.tag, g.b.tag, "the group keeps its tag")
        assertEquals(g.b.device, g.b.records.rootDevice)
        assertEquals(listOf("B", "one", "two"), g.b.devices.map { it.name })
        val set = g.b.records
        assertNotNull(set.refused(listOf(g.root.memberCert)), "the lost phone")
        assertNull(set.refused(listOf(g.one.cert)), "the computer the old root admitted")
        assertNull(set.refused(listOf(g.two.cert, g.adminCA)), "the computer B admitted")
        assertNull(set.refused(g.b.memberChain), "B itself")
        assertEquals(g.b.device, GroupCertificates.verifyMember(g.b.memberChain, g.b.currentRoot, Instant.now()), "B's certificate is from the new root")

        // A computer that gets the records in any order, and the claim times with them, sees the same.
        val computer = RecordSet()
        computer.addAll(g.b.records.records.shuffled(), g.root.groupCA)
        computer.takeClaimTimes(g.b.records.claimTimes)
        assertEquals(g.b.records.digest, computer.digest)
        assertEquals(g.b.roots.map { Key(it) }, computer.roots.map { Key(it) })
        assertEquals(listOf("B", "one", "two"), computer.devices.map { it.name })

        // The new root admits and renews.
        val now = Instant.now()
        val three = Computer(g.b.currentRoot, g.newRootKey, now)
        assertEquals(three.device, GroupCertificates.verifyMember(listOf(three.cert), g.b.trusted, now))
        g.b.record(three.device, "three", "full", three.keyHash, g.newRootKey, now)
        assertNull(g.b.records.refused(listOf(three.cert)))
        val later = now.plusSeconds(500L * 24 * 3600)
        val renewed = assertNotNull(g.b.renewal(listOf(g.one.cert), g.newRootKey, later)).cert
        assertEquals(g.one.device, GroupCertificates.verifyMember(renewed, g.b.currentRoot, later))
    }

    /** Without a delay of the root's, the claim waits 72 hours, and the member signs nothing meanwhile. */
    @Test
    fun claimWaits() {
        val g = group()
        val newRoot = g.newRoot()
        g.claim(newRoot)
        assertEquals("pending", g.b.claimState)
        val f = g.finish(newRoot)
        assertEquals("pending", f.state)
        assertTrue(f.leftMS > 71L * 3600 * 1000, "the group's delay: ${f.leftMS} ms")
        assertNull(f.cert)
        assertFalse(g.b.isRoot)
        assertEquals(g.root.device, g.b.records.rootDevice)
    }

    /**
     * The root hands the group to B (cbb handover): B's claim takes effect
     * at once, and the old root's device stays in the group as a member.
     */
    @Test
    fun handedOver() {
        val now = Instant.now()
        val g = group()
        assertFalse(g.b.handedToMe)
        val h = Records.Body.of("handover", g.rootKey, now)
        h.admin = Records.keyHashOfCert(g.adminCA)
        g.fromRoot(g.root.sign(h, g.rootKey))
        assertTrue(g.b.handedToMe)
        assertFalse(g.root.handedToMe, "the root is no admin to hand the group to")
        g.b.checkHandedOver()
        val newRoot = g.newRoot()
        g.member.claim(CoreMember.Claim.TAKE_HANDED_OVER, newRoot, g.adminKey.publicKeyDER, g.adminCA, g.adminKey::signDigest)
        g.b.claimed(newRoot, null)
        g.b.add(g.member.records())
        assertFalse(g.b.handedToMe, "it claimed the group")
        assertEquals("effective", g.b.claimState, "a handed group needs no wait")
        assertEquals("effective", g.finish(newRoot).state)
        assertTrue(g.b.isRoot)
        assertEquals(g.b.device, g.b.records.rootDevice)
        assertNull(g.b.records.handedTo, "the new root handed nothing")
        assertEquals(listOf("B", "Lost", "one", "two"), g.b.devices.map { it.name }.sorted())
        assertNull(g.b.records.refused(listOf(g.root.memberCert)), "the old root stays a member")

        // A handover to another admin key is not this phone's.
        val other = group()
        val o = Records.Body.of("handover", other.rootKey, now)
        o.admin = Records.keyHash(SoftwareSigner().publicKeyDER)
        other.fromRoot(other.root.sign(o, other.rootKey))
        assertFalse(other.b.handedToMe)
        assertFailsWith<PhoneGroup.Failure> { other.b.checkHandedOver() }
        assertFailsWith<Core.Refusal> {
            other.member.claim(CoreMember.Claim.TAKE_HANDED_OVER, other.newRoot(), other.adminKey.publicKeyDER, other.adminCA, other.adminKey::signDigest)
        }
    }

    /** The root cancels a claim while it waits, and the claimant stays an admin. */
    @Test
    fun claimCancelled() {
        val g = group()
        val newRoot = g.newRoot()
        g.claim(newRoot)
        val e = assertFailsWith<PhoneGroup.Failure> { g.b.checkTakeOver(g.root.device) }
        assertEquals(PhoneGroup.CLAIM_WAITING, e.message)
        val claim = g.claimRecord
        g.root.add(listOf(claim))
        assertEquals(listOf("pending"), g.root.records.claims.map { it.state })
        g.fromRoot(g.root.resolve(listOf(Records.id(claim)), g.rootKey, Instant.now()))
        assertEquals("cancelled", g.finish(newRoot).state)
        assertTrue(g.b.dropEndedClaim())
        assertNull(g.b.claim, "a cancelled claim is dropped")
        assertFalse(g.b.isRoot)
        assertEquals(g.root.device, g.b.records.rootDevice)
    }

    /** The root sets how long a claim waits. */
    @Test
    fun takeoverDelay() {
        val g = group()
        val e = assertFailsWith<PhoneGroup.Failure> { g.root.setTakeoverDelay(8L * 24 * 3600 * 1000, g.rootKey, Instant.now()) }
        assertEquals(PhoneGroup.INVALID_DELAY, e.message)
        assertFailsWith<PhoneGroup.Failure> { g.b.setTakeoverDelay(0, g.adminKey, Instant.now()) }
        g.fromRoot(g.root.setTakeoverDelay(0, g.rootKey, Instant.now()))
        val newRoot = g.newRoot()
        g.claim(newRoot)
        assertEquals("effective", g.finish(newRoot).state, "no delay")
        assertTrue(g.b.isRoot)
    }

    /** The new root signs the old root's settings again, since the state counts only the current root's. */
    @Test
    fun takeOverKeepsSettings() {
        val g = group()
        g.fromRoot(g.root.setKeyLevel(Records.LEVEL_FILES, g.rootKey, Instant.now()))
        assertEquals(Records.LEVEL_FILES, g.b.keyLevel)
        val after = takeOver(g)
        assertTrue(g.b.isRoot)
        assertEquals(Records.LEVEL_FILES, g.b.keyLevel)
        assertEquals(0L to Records.LEVEL_FILES, g.b.settings(Records.keyHash(g.newRootKey.publicKeyDER)))
        assertEquals(1, after.count { Wire.parse(it.body)?.optString("type") == "settings" })
    }

    @Test
    fun oldRootKeyAfterTakeOver() {
        val g = group()
        takeOver(g)
        val set = g.b.records
        // Whoever has the lost phone's root key signs a computer, an admin CA, a device record and a claim: none counts.
        val stolen = Computer(g.root.groupCA, g.rootKey, t0)
        val thiefKey = SoftwareSigner()
        val thiefCA = GroupCertificates.adminCA(SyncEngine.newID(), thiefKey.publicKeyDER, g.root.groupCA, g.rootKey)
        val viaThief = GroupCertificates.member(SyncEngine.newID(), SoftwareSigner().publicKeyDER, thiefCA, thiefKey, t0)
        assertNotNull(set.refused(listOf(stolen.cert)))
        assertNotNull(set.refused(listOf(viaThief, thiefCA)))
        val otherRoot = GroupCertificates.groupCA(SoftwareSigner(), t0, pathLength = 1)
        set.add(set.sign(V2.device(stolen.device, "stolen", "full", stolen.keyHash, g.rootKey, Instant.now()), g.rootKey), g.root.groupCA)
        set.add(set.sign(V2.claim(otherRoot, thiefKey, Instant.now()), thiefKey, thiefCA), g.root.groupCA)
        assertEquals(listOf("B", "one", "two"), set.devices.map { it.name })
        assertEquals(g.b.roots.map { Key(it) }, set.roots.map { Key(it) })
        assertNotNull(set.refused(listOf(stolen.cert)))
    }

    @Test
    fun takeOverRefused() {
        val g = group()
        assertFailsWith<PhoneGroup.Failure> { g.b.checkTakeOver(g.one.device) }
        assertFailsWith<PhoneGroup.Failure> { g.root.checkTakeOver(g.root.device) }
        // The member refuses a claim from a device that does not hold the root too.
        assertFailsWith<Core.Refusal> {
            g.member.claim(CoreMember.Claim.TAKE_OVER, g.newRoot(), g.adminKey.publicKeyDER, g.adminCA, g.adminKey::signDigest, g.one.device)
        }
        // A claim that hands the group to a computer's group CA, or to no root at all, never takes effect.
        val pcCA = GroupCertificates.groupCA(SoftwareSigner(), t0)
        for (root in listOf(pcCA, g.adminCA)) {
            val set = RecordSet.fromJson(g.b.records.toJson())
            set.clock = { t0 }
            set.add(set.sign(V2.claim(root, g.adminKey, t0), g.adminKey, g.adminCA), g.root.groupCA)
            set.clock = { Instant.now() }
            set.refresh()
            assertEquals(emptyList(), set.roots)
        }
    }

    /** A welcome after the takeover names the new root and carries the claim times, and a phone that joins checks it. */
    @Test
    fun welcomeAfterTakeOver() {
        val g = group()
        takeOver(g)
        val t0 = Instant.now()
        val joiner = SyncEngine.newID()
        val key = SoftwareSigner()
        val selfSigned = GroupCertificates.selfSigned(joiner, key)
        val cert = GroupCertificates.member(joiner, key.publicKeyDER, g.b.currentRoot, g.newRootKey, t0)
        val w = Pairing.Welcome(cert, g.b.groupCA, roots = g.b.roots, records = g.b.records.pathRecords, claimTimes = g.b.records.claimTimes)
        val j = PairingJoiner.Joined(joiner, w, Pairing.MemberAD(g.b.device, g.b.tag))
        val info = Pairing.Info("C", "android")
        PairingJoiner.check(j, info, g.b.memberCert, selfSigned, t0)
        val bad = PairingJoiner.Joined(joiner, Pairing.Welcome(cert, g.b.groupCA, records = w.records, claimTimes = w.claimTimes), j.member)
        assertFailsWith<PairingJoiner.Failure> { PairingJoiner.check(bad, info, g.b.memberCert, selfSigned, t0) }
        // A root that no record leads to, as one an admin made up and named in the Welcome, is refused.
        val made = PairingJoiner.Joined(joiner, Pairing.Welcome(cert, g.b.groupCA, roots = g.b.roots), j.member)
        assertFailsWith<PairingJoiner.Failure> { PairingJoiner.check(made, info, g.b.memberCert, selfSigned, t0) }
        assertEquals(g.b.roots.map { Key(it) }, PhoneGroup.joined(j).roots.map { Key(it) })
    }

    /** Every record the set holds goes to a forwarder, which sees the same roots and the lost phone removed. */
    @Test
    fun authorityRecords() {
        val g = group()
        val rs = takeOver(g)
        val after = g.b.records.authorityRecords
        val ids = after.map { Key(Records.id(it)) }.toSet()
        assertTrue(rs.all { Key(Records.id(it)) in ids }, "the takeover's records")
        assertEquals(ids.size, after.size)
        val forwarder = RecordSet()
        forwarder.clock = { t0 }
        forwarder.addAll(after.shuffled(), g.root.groupCA)
        forwarder.clock = { Instant.now() }
        forwarder.refresh()
        assertEquals(g.b.roots.map { Key(it) }, forwarder.roots.map { Key(it) })
        assertNotNull(forwarder.refused(listOf(g.root.memberCert)))
    }

    /** Writes swift-root.json for internal/group's TestSwiftRoot: a takeover as the core's member signs it for this kit. */
    @Test
    fun takeOverForGo() {
        val dir = Interop.out ?: return
        val g = group()
        takeOver(g)
        File(dir, "swift-root.json").writeBytes(
            Wire.encode(
                Wire.obj(
                    "group_ca" to Wire.bytes(g.root.groupCA),
                    "records" to JsonArray(g.b.records.records.reversed().map { it.toJson() }),
                    "claim_times" to JsonArray(g.b.records.claimTimes.map { it.toJson() }),
                    "roots" to Wire.list(g.b.roots),
                    "devices" to JsonArray(g.b.devices.map { Wire.str(it.id)!! }),
                    "digest" to Wire.str(g.b.records.digest ?: ""),
                    "lost" to Wire.bytes(g.root.memberCert),
                    "kept" to Wire.bytes(g.one.cert),
                ),
            ),
        )
    }
}
