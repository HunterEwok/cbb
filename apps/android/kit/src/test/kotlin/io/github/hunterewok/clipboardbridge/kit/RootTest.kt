// SPDX-License-Identifier: AGPL-3.0-only

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.JsonArray
import java.io.File
import java.time.Instant
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
 * root, which takes effect after the delay.
 */
class RootTest {
    /** When the group was made: long enough ago that a claim made then took effect by now. */
    private val t0 = Instant.now().minusSeconds(100L * 3600)

    /** A computer: its device ID, key and member certificate. */
    class Computer(ca: ByteArray, signer: CertificateSigner, now: Instant) {
        val device = SyncEngine.newID()
        val key = SoftwareSigner()
        val cert = GroupCertificates.member(device, key.publicKeyDER, ca, signer, now)
        val keyHash: ByteArray get() = Records.keyHashOfCert(cert)
    }

    /** The group before the loss: the root phone, which admitted computer one itself, and admin phone B, which admitted computer two. */
    class Group(now: Instant) {
        val rootKey = SoftwareSigner()
        val adminKey = SoftwareSigner()
        val newRootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, now, "Lost")
        private val bDevice = SyncEngine.newID()

        /** B's admin CA, under the old root. */
        val adminCA = GroupCertificates.adminCA(bDevice, adminKey.publicKeyDER, root.groupCA, rootKey)
        private val bCert = GroupCertificates.member(bDevice, SoftwareSigner().publicKeyDER, root.groupCA, rootKey, now)
        val b = PhoneGroup(bDevice, root.groupCA, bCert)
        val one = Computer(root.groupCA, rootKey, now)
        val two = Computer(adminCA, adminKey, now)

        init {
            // The members held every record since now.
            root.records.clock = { now }
            b.records.clock = { now }
            root.record(bDevice, "B", "phone", Records.keyHashOfCert(bCert), rootKey, now, Records.keyHashOfCert(adminCA))
            root.record(one.device, "one", "full", one.keyHash, rootKey, now)
            b.isRoot = false
            b.adminCA = adminCA
            b.add(root.records.records)
            b.record(two.device, "two", "full", two.keyHash, adminKey, now)
            root.add(b.records.records)
            root.records.clock = { Instant.now() }
        }
    }

    /** B's claim, made at t0, and B as the root once it took effect. */
    private fun takeOver(g: Group): Pair<Member.Record, List<Member.Record>> {
        val newRoot = GroupCertificates.groupCA(g.newRootKey, t0, pathLength = 1)
        val claim = g.b.takeOver(g.root.device, g.adminKey, newRoot, t0)
        assertEquals("pending", g.b.claimState)
        assertFalse(g.b.isRoot)
        assertTrue(g.b.finishTakeOver(g.newRootKey, t0).isEmpty(), "the claim waits")
        g.b.records.clock = { Instant.now() }
        return claim to g.b.finishTakeOver(g.newRootKey, Instant.now())
    }

    @Test
    fun takeOver() {
        val g = Group(t0)
        val lost = g.root.device
        assertEquals(lost, g.b.records.rootDevice)
        val (_, rs) = takeOver(g)
        assertEquals(2, rs.size, "B's own device and the removal of the lost phone")
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

        // A computer that gets the records in any order, and the claim times with them, sees the same.
        val computer = RecordSet()
        computer.addAll(g.b.records.records.shuffled(), g.root.groupCA)
        computer.takeClaimTimes(g.b.records.claimTimes)
        assertEquals(g.b.records.digest, computer.digest)
        assertEquals(g.b.roots.map { Key(it) }, computer.roots.map { Key(it) })
        assertEquals(listOf("B", "one", "two"), computer.devices.map { it.name })
        // Without them, it waits the delay itself.
        val late = RecordSet()
        late.addAll(g.b.records.records, g.root.groupCA)
        assertEquals(emptyList(), late.roots)
        assertEquals(listOf("pending"), late.claims.map { it.state })

        // The new root admits and renews.
        val three = Computer(g.b.currentRoot, g.newRootKey, t0)
        assertEquals(three.device, GroupCertificates.verifyMember(listOf(three.cert), g.b.trusted, t0))
        g.b.record(three.device, "three", "full", three.keyHash, g.newRootKey, Instant.now())
        assertNull(g.b.records.refused(listOf(three.cert)))
        val later = t0.plusSeconds(500L * 24 * 3600)
        val renewed = assertNotNull(g.b.renewal(listOf(g.one.cert), g.newRootKey, later)).cert
        assertEquals(g.one.device, GroupCertificates.verifyMember(renewed, g.b.currentRoot, later))
    }

    /**
     * The root hands the group to B (cbb handover): B's claim takes effect
     * at once, and the old root's device stays in the group as a member.
     */
    @Test
    fun handedOver() {
        val now = Instant.now()
        val g = Group(now)
        assertFalse(g.b.handedToMe)
        val h = Records.Body.of("handover", g.rootKey, now)
        h.admin = Records.keyHashOfCert(g.adminCA)
        g.b.add(listOf(g.root.sign(h, g.rootKey)))
        assertTrue(g.b.handedToMe)
        assertFalse(g.root.handedToMe, "the root is no admin to hand the group to")
        val newRoot = GroupCertificates.groupCA(g.newRootKey, now, pathLength = 1)
        g.b.takeHandedOver(g.adminKey, newRoot, now)
        assertFalse(g.b.handedToMe, "it claimed the group")
        assertEquals("effective", g.b.claimState, "a handed group needs no wait")
        val rs = g.b.finishTakeOver(g.newRootKey, now)
        assertEquals(1, rs.size, "B's own device; nothing removed")
        assertTrue(g.b.isRoot)
        assertEquals(g.b.device, g.b.records.rootDevice)
        assertNull(g.b.records.handedTo, "the new root handed nothing")
        assertEquals(listOf("B", "Lost", "one", "two"), g.b.devices.map { it.name }.sorted())
        assertNull(g.b.records.refused(listOf(g.root.memberCert)), "the old root stays a member")

        // A handover to another admin key is not this phone's.
        val other = Group(now)
        val o = Records.Body.of("handover", other.rootKey, now)
        o.admin = Records.keyHash(SoftwareSigner().publicKeyDER)
        other.b.add(listOf(other.root.sign(o, other.rootKey)))
        assertFalse(other.b.handedToMe)
        assertFailsWith<PhoneGroup.Failure> { other.b.takeHandedOver(other.adminKey, newRoot, now) }
    }

    /** The root cancels a claim while it waits, and the claimant stays an admin. */
    @Test
    fun claimCancelled() {
        val g = Group(t0)
        val newRoot = GroupCertificates.groupCA(g.newRootKey, t0, pathLength = 1)
        val claim = g.b.takeOver(g.root.device, g.adminKey, newRoot, t0)
        val e = assertFailsWith<PhoneGroup.Failure> { g.b.takeOver(g.root.device, g.adminKey, newRoot, t0) }
        assertEquals(PhoneGroup.CLAIM_WAITING, e.message)
        g.root.add(listOf(claim))
        assertEquals(listOf("pending"), g.root.records.claims.map { it.state })
        val cancel = g.root.resolve(listOf(Records.id(claim)), g.rootKey, Instant.now())
        g.b.add(listOf(cancel))
        g.b.records.clock = { Instant.now() }
        assertTrue(g.b.finishTakeOver(g.newRootKey, Instant.now()).isEmpty())
        assertNull(g.b.claim, "a cancelled claim is dropped")
        assertFalse(g.b.isRoot)
        assertEquals(g.root.device, g.b.records.rootDevice)
    }

    /** The root sets how long a claim waits. */
    @Test
    fun takeoverDelay() {
        val g = Group(t0)
        val e = assertFailsWith<PhoneGroup.Failure> { g.root.setTakeoverDelay(8L * 24 * 3600 * 1000, g.rootKey, Instant.now()) }
        assertEquals(PhoneGroup.INVALID_DELAY, e.message)
        assertFailsWith<PhoneGroup.Failure> { g.b.setTakeoverDelay(0, g.adminKey, Instant.now()) }
        val r = g.root.setTakeoverDelay(0, g.rootKey, Instant.now())
        g.b.add(listOf(r))
        g.b.records.clock = { Instant.now() }
        val newRoot = GroupCertificates.groupCA(g.newRootKey, t0, pathLength = 1)
        g.b.takeOver(g.root.device, g.adminKey, newRoot, Instant.now())
        assertTrue(g.b.finishTakeOver(g.newRootKey, Instant.now()).isNotEmpty(), "no delay")
        assertTrue(g.b.isRoot)
    }

    /** The new root signs the old root's settings again, since the state counts only the current root's. */
    @Test
    fun takeOverKeepsSettings() {
        val g = Group(t0)
        g.b.records.clock = { t0 }
        g.b.add(listOf(g.root.setTakeoverDelay(3_600_000, g.rootKey, t0), g.root.setKeyLevel(Records.LEVEL_FILES, g.rootKey, t0)))
        assertEquals(Records.LEVEL_FILES, g.b.keyLevel)
        val (_, after) = takeOver(g)
        assertTrue(g.b.isRoot)
        assertEquals(Records.LEVEL_FILES, g.b.keyLevel)
        assertEquals(3_600_000L to Records.LEVEL_FILES, g.b.settings(Records.keyHash(g.newRootKey.publicKeyDER)))
        assertEquals(1, after.count { Wire.parse(it.body)?.optString("type") == "settings" })
    }

    @Test
    fun oldRootKeyAfterTakeOver() {
        val g = Group(t0)
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
        val g = Group(t0)
        val newRoot = GroupCertificates.groupCA(g.newRootKey, t0, pathLength = 1)
        assertFailsWith<PhoneGroup.Failure> { g.b.takeOver(g.one.device, g.adminKey, newRoot, t0) }
        assertFailsWith<PhoneGroup.Failure> { g.root.takeOver(g.root.device, g.rootKey, newRoot, t0) }
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
        val g = Group(t0)
        takeOver(g)
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
        // A root that no record leads to, as one an admin made up and named in the Welcome, is refused; so is one
        // whose claim still waits for the joiner, without the claim times.
        val made = PairingJoiner.Joined(joiner, Pairing.Welcome(cert, g.b.groupCA, roots = g.b.roots), j.member)
        assertFailsWith<PairingJoiner.Failure> { PairingJoiner.check(made, info, g.b.memberCert, selfSigned, t0) }
        val early = PairingJoiner.Joined(joiner, Pairing.Welcome(cert, g.b.groupCA, roots = g.b.roots, records = w.records), j.member)
        assertFailsWith<PairingJoiner.Failure> { PairingJoiner.check(early, info, g.b.memberCert, selfSigned, t0) }
        assertEquals(g.b.roots.map { Key(it) }, PhoneGroup.joined(j).roots.map { Key(it) })
    }

    /** Every record the set holds goes to a forwarder, which sees the same roots and the lost phone removed. */
    @Test
    fun authorityRecords() {
        val g = Group(t0)
        val (claim, rs) = takeOver(g)
        val after = g.b.records.authorityRecords
        val ids = after.map { Key(Records.id(it)) }.toSet()
        assertTrue((rs + claim).all { Key(Records.id(it)) in ids }, "the takeover's records")
        assertEquals(ids.size, after.size)
        val forwarder = RecordSet()
        forwarder.clock = { t0 }
        forwarder.addAll(after.shuffled(), g.root.groupCA)
        forwarder.clock = { Instant.now() }
        forwarder.refresh()
        assertEquals(g.b.roots.map { Key(it) }, forwarder.roots.map { Key(it) })
        assertNotNull(forwarder.refused(listOf(g.root.memberCert)))
    }

    /** Writes swift-root.json for internal/group's TestSwiftRoot: a takeover as this kit signs it. */
    @Test
    fun takeOverForGo() {
        val dir = Interop.out ?: return
        val g = Group(t0)
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
