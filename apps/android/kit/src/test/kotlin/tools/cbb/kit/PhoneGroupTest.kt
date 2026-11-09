// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.security.SecureRandom
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A second phone joins a phone group and becomes an admin (docs/protocol.md,
 * sections 6 and 10), then admits, renews and is removed; and a computer
 * becomes an admin.
 */
class PhoneGroupTest {
    private val t0 = Instant.now()
    private val later = t0.plusSeconds(500L * 24 * 3600)
    private val sid = ByteArray(32).also { SecureRandom().nextBytes(it) }

    /** A device that listens for pairing: its device ID, member key and self-signed certificate. */
    class Listener {
        val device = SyncEngine.newID()
        val key = SoftwareSigner()
        val cert = GroupCertificates.selfSigned(device, key)
    }

    /** Runs one pairing: the admitting phone dials the listener, which answers with joinerCode (code when null). */
    private fun pair(
        admitter: PhoneGroup,
        signer: CertificateSigner,
        l: Listener,
        info: Pairing.Info,
        admin: CertificateSigner? = null,
        code: String = "123456",
        joinerCode: String? = null,
        makeAdmin: Boolean = true,
        addrs: List<String> = emptyList(),
    ): Pair<Result<PairingMember.Admitted>, Result<PairingJoiner.Joined>> {
        // With admin, the key info's adminKey names, the joiner proves it for the session.
        @Suppress("NAME_SHADOWING")
        val info = admin?.let { info.proving(sid, it) } ?: info
        val (m, j) = Pipe.pair()
        val member = Background { admitter.admit(m, code, l.cert, sid, signer, t0, makeAdmin, addrs) }
        val joined = runCatching {
            PairingJoiner.accept(j, joinerCode ?: code, info, admitter.memberCert, l.cert, sid, t0) {}
        }
        j.close()
        return runCatching { member.join() } to joined
    }

    @Test
    fun secondPhoneBecomesAdmin() {
        val rootKey = SoftwareSigner()
        val seal = Interop.read("go-sealed-commands.json").jsonObject.optBytes("public")!!
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0, "First", seal)
        assertEquals(root.device, root.records.rootDevice)
        assertTrue(root.devices.first { it.id == root.device }.seal.contentEqualsOrNull(seal), "the root phone's own key for sealed messages")

        // The second phone joins with an admin key and gets its admin CA.
        val second = Listener()
        val adminKey = SoftwareSigner()
        val (m, j) = pair(root, rootKey, second, Pairing.Info("Second", "android", adminKey.publicKeyDER, seal = seal), adminKey)
        val joined = j.getOrThrow()
        assertTrue(m.getOrThrow().confirmed)
        assertEquals(second.device, joined.device)
        val adminCA = assertNotNull(joined.welcome.adminCA)
        GroupCertificates.checkAdminCA(adminCA, root.groupCA)
        assertTrue(root.computers.isEmpty(), "a phone is no computer")
        val listed = assertNotNull(root.devices.firstOrNull { it.id == second.device })
        assertEquals("phone", listed.role)
        assertTrue(listed.admin)
        assertTrue(listed.seal.contentEqualsOrNull(seal), "a phone's key for sealed messages, from its pairing")

        val admin = PhoneGroup.joined(joined)
        assertFalse(admin.isRoot)
        assertTrue(admin.isAdmin)
        assertEquals(root.tag, admin.tag)
        // The records reach it through the computers.
        admin.add(root.records.records)
        assertEquals(root.device, admin.records.rootDevice)

        // The admin admits a computer from its own admin CA.
        val pc = Listener()
        val (_, j2) = pair(admin, adminKey, pc, Pairing.Info("pi", "linux"))
        val pcJoined = j2.getOrThrow()
        assertContentEquals(adminCA, pcJoined.welcome.issuer)
        assertNull(pcJoined.welcome.adminCA)
        val pcChain = listOf(pcJoined.welcome.cert, adminCA)
        assertEquals(pc.device, GroupCertificates.verifyMember(pcChain, root.groupCA, t0))
        assertEquals(listOf(pc.device), admin.computers.map { it.device })
        root.add(admin.records.records)
        assertTrue(root.devices.any { it.id == pc.device }, "a record signed through the admin CA counts")
        // The root and the admin may be the hub away from home; a plain member may not.
        assertTrue(root.records.mayHost(root.device))
        assertTrue(root.records.mayHost(second.device))
        assertFalse(root.records.mayHost(pc.device))
        // By key: the root's own chain and the admin's, not another device's under their IDs.
        assertTrue(root.records.mayHost(root.device, root.memberChain))
        assertTrue(root.records.mayHost(second.device, admin.memberChain))
        assertFalse(root.records.mayHost(pc.device, pcChain), "a chain whose key no admin record names")
        assertFalse(root.records.mayHost(root.device, admin.memberChain))

        // Renewals: an admin renews what it issued, and what the root issued, from its admin CA; the root renews any.
        val byAdmin = assertNotNull(admin.renewal(pcChain, adminKey, later))
        assertContentEquals(adminCA, byAdmin.issuer)
        assertEquals(pc.device, GroupCertificates.verifyMember(byAdmin.cert, root.groupCA, later, adminCA))
        val rootsOne = assertNotNull(admin.renewal(listOf(root.memberCert), adminKey, later))
        assertEquals(root.device, GroupCertificates.verifyMember(rootsOne.cert, root.groupCA, later, adminCA))
        val byRoot = assertNotNull(root.renewal(pcChain, rootKey, later)).cert
        assertEquals(pc.device, GroupCertificates.verifyMember(byRoot, root.groupCA, later))
        assertTrue(admin.renewOwnCertificate(adminKey, later))
        assertContentEquals(adminCA, admin.memberIssuer)
        assertEquals(admin.device, GroupCertificates.verifyMember(admin.memberChain, root.groupCA, later))

        // The admin cannot remove the root; the root removes the admin and every listed device stays: the
        // computer it admitted, and the root, whose certificate it renewed (docs/protocol.md, section 10, "Removals and
        // freezes keep what the author saw").
        assertFailsWith<PhoneGroup.Failure> { admin.revoke(root.device, adminKey, t0) }
        val revocation = root.revoke(second.device, rootKey, t0)
        val body = Json.parseToJsonElement(String(revocation.body)).jsonObject
        assertEquals("revoke", body.str("type"))
        assertEquals(setOf(Key(listed.key), Key(Records.keyHashOfCert(adminCA))), body.getValue("keys").jsonArray.map { Key(b64(it.jsonPrimitive.content)) }.toSet())
        assertFalse(root.devices.any { it.id == second.device })
        assertTrue(root.devices.any { it.id == pc.device })
        assertNull(root.records.refused(pcChain))
        assertNull(root.records.refused(listOf(rootsOne.cert, adminCA)), "the root's certificate the removed admin renewed")
        assertNotNull(root.records.refused(listOf(joined.welcome.cert)))
    }

    /** A signer that counts its signatures. */
    private class Counting : CertificateSigner {
        private val key = SoftwareSigner()
        var made = 0
        override val publicKeyDER get() = key.publicKeyDER
        override fun signature(data: ByteArray): ByteArray = key.signature(data).also { made++ }
    }

    /**
     * How many signatures each action makes: on Android each asks the user,
     * and the app's prompts say "Signature 2 of 5" by these counts
     * (LiveGroup's Prompts), so a change here changes them too.
     */
    @Test
    fun signaturesPerAction() {
        val root = Counting()
        val g = PhoneGroup.create(root, SoftwareSigner().publicKeyDER, t0)
        assertEquals(3, root.made, "making a group")
        for (i in 1..2) {
            root.made = 0
            val (m, j) = pair(g, root, Listener(), Pairing.Info("pi", "linux"))
            j.getOrThrow()
            m.getOrThrow()
            assertEquals(2, root.made, "admitting a computer")
        }
        root.made = 0
        g.makeRecovery(root, t0)
        assertEquals(2, root.made, "making the recovery key")
    }

    @Test
    fun phoneWithoutAdmin() {
        val rootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0)
        val l = Listener()
        val third = SoftwareSigner()
        val (_, j) = pair(root, rootKey, l, Pairing.Info("Third", "ios", third.publicKeyDER), third, makeAdmin = false)
        val joined = j.getOrThrow()
        assertNull(joined.welcome.adminCA)
        assertEquals(false, root.devices.firstOrNull { it.id == l.device }?.admin)
        val g = PhoneGroup.joined(joined)
        assertFalse(g.isAdmin)
        assertFailsWith<PhoneGroup.Failure> { g.revoke(root.device, rootKey, t0) }
        assertFalse(g.renewOwnCertificate(rootKey, later))

        // An admin that is not the root makes no admins.
        val adminKey = SoftwareSigner()
        val (_, j2) = pair(root, rootKey, Listener(), Pairing.Info("Admin", "ios", adminKey.publicKeyDER), adminKey)
        val admin = PhoneGroup.joined(j2.getOrThrow())
        val fourth = SoftwareSigner()
        val (_, j3) = pair(admin, adminKey, Listener(), Pairing.Info("Fourth", "android", fourth.publicKeyDER), fourth)
        assertNull(j3.getOrThrow().welcome.adminCA)
    }

    @Test
    fun memberWithoutAdmin() {
        val rootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0)
        val l = Listener()
        val addrs = listOf("192.168.20.5:8764", "203.0.113.7:8764", "[fd00::5]:8764", "[2001:db8::5]:8764")
        val (_, j) = pair(root, rootKey, l, Pairing.Info("router", "linux", caps = listOf("dials", "hub")), addrs = addrs)
        // Only the home network addresses are kept, to dial it when mDNS does not reach its subnet.
        assertEquals(mapOf(l.device to listOf("192.168.20.5:8764", "[fd00::5]:8764")), root.addresses)
        val welcome = j.getOrThrow().welcome
        assertNull(welcome.adminCA)
        val d = root.devices.first { it.id == l.device }
        assertEquals("member", d.role)
        assertEquals(listOf("dials", "hub"), d.caps)
        assertFailsWith<PhoneGroup.Failure> { root.makeAdmin(l.device, SoftwareSigner().publicKeyDER, rootKey, t0, allowFileKey = true) }
    }

    @Test
    fun wrongCode() {
        val rootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0)
        val (m, j) = pair(root, rootKey, Listener(), Pairing.Info("Second", "android"), joinerCode = "654321")
        assertEquals(Pairing.ErrorCode.WRONG_CODE, (j.exceptionOrNull() as PairingJoiner.Failure).code)
        assertEquals(Pairing.ErrorCode.WRONG_CODE, (m.exceptionOrNull() as PairingMember.Failure).code)
    }

    @Test
    fun joinerRefusesAWelcomeForAnotherKey() {
        val rootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0)
        val l = Listener()
        val (m, j) = Pipe.pair()
        val member = Background {
            PairingMember.admit(m, "123456", root.memberCert, l.cert, sid, Pairing.MemberAD(root.device, root.tag)) { dev, _, _ ->
                Pairing.Welcome(GroupCertificates.member(dev, SoftwareSigner().publicKeyDER, root.groupCA, rootKey, t0), root.groupCA)
            }
        }
        val e = assertFailsWith<PairingJoiner.Failure> {
            PairingJoiner.accept(j, "123456", Pairing.Info("Second", "android"), root.memberCert, l.cert, sid, t0) { error("stored a bad welcome") }
        }
        assertEquals("the certificate is not for this phone", e.message)
        assertFalse(member.join().confirmed)
    }

    @Test
    fun memberRefusesAJoinerKeyOrChainAsAComputerDoes() {
        val root = PhoneGroup.create(SoftwareSigner(), SoftwareSigner().publicKeyDER, t0)
        val l = Listener()
        val p384 = java.util.Base64.getDecoder().decode(P384_CERT)
        val (m, _) = Pipe.pair()
        val two = object : FrameTransport by m {
            override val peerChain = listOf(l.cert, root.memberCert)
        }
        for ((t, cert, why) in listOf(
            Triple(m, p384, "the joining device's key is not a P-256 key"),
            Triple(two, l.cert, "the joining device must send exactly one certificate"),
        )) {
            val e = assertFailsWith<PairingMember.Failure> {
                PairingMember.admit(t, "123456", root.memberCert, cert, sid, Pairing.MemberAD(root.device, root.tag)) { _, _, _ ->
                    error("issued a welcome")
                }
            }
            assertEquals(why, e.message)
        }
    }

    @Test
    fun saveAndLoad() {
        val rootKey = SoftwareSigner()
        val g = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0, "My\u0007Pixel")
        assertEquals(listOf("MyPixel"), g.devices.map { it.name })
        val pi = SyncEngine.newID()
        val cert = GroupCertificates.member(pi, SoftwareSigner().publicKeyDER, g.groupCA, rootKey, t0)
        g.record(pi, "pi", "member", Records.keyHashOfCert(cert), rootKey, t0, caps = Records.CAPS)
        g.computers.add(PhoneGroup.Computer(pi, "pi", "linux", cert, Instant.ofEpochMilli(t0.toEpochMilli()), listOf("10.0.0.5:8764")))
        g.setKeyLevel(Records.LEVEL_FILES, rootKey, t0)
        val (ca, _) = g.makeAdmin(pi, SoftwareSigner().publicKeyDER, rootKey, t0.plusSeconds(1), allowFileKey = true)
        val f = File.createTempFile("group", ".json")
        try {
            g.save(f)
            val back = assertNotNull(PhoneGroup.load(f))
            assertEquals(g.device, back.device)
            assertContentEquals(g.memberCert, back.memberCert)
            assertEquals(g.computers, back.computers)
            assertEquals(g.records.digest, back.records.digest)
            assertEquals(g.devices, back.devices)
            assertContentEquals(ca, back.computerAdmins[pi])
            assertTrue(back.isRoot)
        } finally {
            f.delete()
        }
        assertEquals("Android", PhoneGroup.validName("\u0001"))
        assertEquals(64, PhoneGroup.validName("\u0436".repeat(40)).toByteArray().size)
    }

    /**
     * A phone joins as a member, and the root makes it an admin later with the
     * admin key its hello offers (protocol.md, section 10, "Admins"); the phone
     * takes the admin CA only for its own key and device, from the current
     * root.
     */
    @Test
    fun makePhoneAdmin() {
        val rootKey = SoftwareSigner()
        val g = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0)
        val phone = SyncEngine.newID()
        val cert = GroupCertificates.member(phone, SoftwareSigner().publicKeyDER, g.groupCA, rootKey, t0)
        g.record(phone, "Pixel", "phone", Records.keyHashOfCert(cert), rootKey, t0, os = "android", store = Records.HARDWARE)
        val t1 = t0.plusSeconds(1)
        assertFailsWith<PhoneGroup.Failure> { g.makeAdmin(g.device, SoftwareSigner().publicKeyDER, rootKey, t1) }
        // The root's key is refused: it would hand the phone a second device's admin CA.
        assertFailsWith<PhoneGroup.Failure> { g.makeAdmin(phone, rootKey.publicKeyDER, rootKey, t1) }
        val adminKey = SoftwareSigner()
        // The phone's store is its record's, whatever the hello says.
        val (ca, r) = g.makeAdmin(phone, adminKey.publicKeyDER, rootKey, t1, keyStore = Records.FILE)
        assertTrue(g.records.records.contains(r))
        val d = g.devices.first { it.id == phone }
        assertTrue(d.admin)
        assertEquals("phone", d.role)
        assertEquals(Records.HARDWARE, d.store)
        assertEquals(Records.POWERS.toSet(), d.powers.toSet())
        assertFailsWith<PhoneGroup.Failure> { g.makeAdmin(phone, SoftwareSigner().publicKeyDER, rootKey, t1) }

        // The member phone's side.
        val saved = kotlinx.serialization.json.Json.parseToJsonElement(String(g.toJson())) as kotlinx.serialization.json.JsonObject
        val member = PhoneGroup.fromJson(
            kotlinx.serialization.json.JsonObject(saved + ("device" to kotlinx.serialization.json.JsonPrimitive(phone))).toString().toByteArray(),
        )
        member.isRoot = false
        member.adminCA = null
        assertFailsWith<PhoneGroup.Failure>("another key") { member.takeAdminCA(ca, SoftwareSigner().publicKeyDER) }
        val foreignRoot = SoftwareSigner()
        val foreign = GroupCertificates.adminCA(phone, adminKey.publicKeyDER, PhoneGroup.create(foreignRoot, SoftwareSigner().publicKeyDER, t0).groupCA, foreignRoot)
        assertFailsWith<PhoneGroup.Failure>("another root") { member.takeAdminCA(foreign, adminKey.publicKeyDER) }
        val other = GroupCertificates.adminCA(SyncEngine.newID(), adminKey.publicKeyDER, g.groupCA, rootKey)
        assertFailsWith<PhoneGroup.Failure>("another device") { member.takeAdminCA(other, adminKey.publicKeyDER) }
        assertFalse(member.isAdmin)
        member.takeAdminCA(ca, adminKey.publicKeyDER)
        assertTrue(member.isAdmin)
        assertContentEquals(ca, member.adminCA)
        assertFailsWith<PhoneGroup.Failure> { member.takeAdminCA(ca, adminKey.publicKeyDER) }
    }

    /** The key level decides who may be an admin; the root sets it, keeping the takeover delay, and never above its own key. */
    @Test
    fun keyLevel() {
        val root = SoftwareSigner()
        val g = PhoneGroup.create(root, SoftwareSigner().publicKeyDER, t0)
        assertEquals(Records.HARDWARE, g.keyLevel)
        val pi = SyncEngine.newID()
        g.record(pi, "pi", "member", Records.keyHashOfCert(GroupCertificates.member(pi, SoftwareSigner().publicKeyDER, g.groupCA, root, t0)), root, t0, caps = Records.CAPS)
        val adminKey = SoftwareSigner().publicKeyDER
        val t1 = t0.plusSeconds(1)
        // At the level hardware a key in a file is no admin, even with the consent.
        assertFailsWith<PhoneGroup.BelowKeyLevel> { g.makeAdmin(pi, adminKey, root, t1, keyStore = Records.FILE, allowFileKey = true) }
        // The root's own key is not proven, so the level proven is out of its reach.
        assertFailsWith<PhoneGroup.BelowKeyLevel> { g.setKeyLevel(Records.PROVEN, root, t1) }
        assertEquals(PhoneGroup.INVALID_KEY_LEVEL, assertFailsWith<PhoneGroup.Failure> { g.setKeyLevel("any", root, t1) }.message)
        g.setTakeoverDelay(3_600_000, root, t1)
        g.setKeyLevel(Records.LEVEL_FILES, root, t1)
        assertEquals(Records.LEVEL_FILES, g.keyLevel)
        assertEquals(3_600_000L, g.settings(Records.keyHash(root.publicKeyDER)).first, "the level keeps the delay")
        g.makeAdmin(pi, adminKey, root, t1, keyStore = Records.FILE, allowFileKey = true)
        assertEquals(listOf(pi), g.belowKeyLevel(Records.HARDWARE))
        assertEquals(emptyList(), g.belowKeyLevel(Records.LEVEL_FILES))
        g.setTakeoverDelay(0, root, t1)
        assertEquals(Records.LEVEL_FILES, g.keyLevel, "the delay keeps the level")
        g.isRoot = false
        assertFailsWith<PhoneGroup.Failure> { g.setKeyLevel(Records.HARDWARE, root, t1) }
    }

    @Test
    fun rename() {
        val root = SoftwareSigner()
        val g = PhoneGroup.create(root, SoftwareSigner().publicKeyDER, t0)
        val pi = SyncEngine.newID()
        val piKey = Records.keyHashOfCert(GroupCertificates.member(pi, SoftwareSigner().publicKeyDER, g.groupCA, root, t0))
        g.record(pi, "pi", "member", piKey, root, t0, os = "linux", caps = Records.CAPS)
        g.setKeyLevel(Records.LEVEL_FILES, root, t0)
        val (ca, _) = g.makeAdmin(pi, SoftwareSigner().publicKeyDER, root, t0.plusSeconds(1), allowFileKey = true)
        val r = g.rename(pi, "  living room pi ", root, t0.plusSeconds(2))
        assertTrue(r in g.records.records)
        val d = assertNotNull(g.devices.firstOrNull { it.id == pi })
        assertEquals("living room pi", d.name)
        assertTrue(d.admin)
        assertContentEquals(Records.keyHashOfCert(ca), d.adminKey)
        assertContentEquals(piKey, d.key)
        assertEquals("member", d.role)
        assertEquals("linux", d.os)
        assertFailsWith<PhoneGroup.Failure> { g.rename(pi, " ", root, t0) }
        assertFailsWith<PhoneGroup.Failure> { g.rename(pi, "x".repeat(65), root, t0) }
        assertFailsWith<PhoneGroup.Failure> { g.rename(SyncEngine.newID(), "x", root, t0) }
    }

    /** The watch's emergency actions (section 10, "Watches"): the phone builds the body, the watch signs it, and it counts as the rules say. */
    @Test
    fun watchActions() {
        val root = SoftwareSigner()
        val g = PhoneGroup.create(root, SoftwareSigner().publicKeyDER, t0)
        val pi = SyncEngine.newID()
        g.record(pi, "pi", "member", Records.keyHashOfCert(GroupCertificates.member(pi, SoftwareSigner().publicKeyDER, g.groupCA, root, t0)), root, t0, caps = Records.CAPS)
        g.setKeyLevel(Records.LEVEL_FILES, root, t0)
        g.makeAdmin(pi, SoftwareSigner().publicKeyDER, root, t0.plusSeconds(1), allowFileKey = true)
        val deck = SyncEngine.newID()
        g.record(deck, "deck", "member", Records.keyHashOfCert(GroupCertificates.member(deck, SoftwareSigner().publicKeyDER, g.groupCA, root, t0)), root, t0, caps = Records.CAPS)
        val watchKey = SoftwareSigner()
        val watch = SyncEngine.newID()
        val (ca, _) = g.addWatch(watch, "Watch", "wearos", watchKey.publicKeyDER, root, t0.plusSeconds(1))
        val all = listOf(PhoneGroup.WatchAction.PASTE_OFF, PhoneGroup.WatchAction.ACTIONS_OFF, PhoneGroup.WatchAction.AWAY_OFF, PhoneGroup.WatchAction.ACTION)
        assertEquals(listOf(PhoneGroup.WatchAction.FREEZE) + all, g.watchActions(pi))
        assertEquals(listOf(PhoneGroup.WatchAction.REMOVE) + all, g.watchActions(deck))
        assertEquals(emptyList(), g.watchActions(g.device))
        assertEquals(emptyList(), g.watchActions(watch))
        assertFailsWith<PhoneGroup.Failure> { g.watchBody(PhoneGroup.WatchAction.REMOVE, pi, watch, t0) }
        assertFailsWith<PhoneGroup.Failure> { g.watchBody(PhoneGroup.WatchAction.FREEZE, pi, deck, t0) }
        val t2 = t0.plusSeconds(2)
        fun signed(a: PhoneGroup.WatchAction, device: String, name: String? = null): Member.Record {
            val body = g.watchBody(a, device, watch, t2, name)
            return PhoneGroup.watchRecord(body, watchKey.signature(body), ca)
        }
        val now = t0.plusSeconds(3).toEpochMilli()
        for (a in listOf(PhoneGroup.WatchAction.PASTE_OFF, PhoneGroup.WatchAction.ACTIONS_OFF, PhoneGroup.WatchAction.AWAY_OFF)) {
            Commands.verify(signed(a, pi), g.records, pi, now)
        }
        Commands.verify(signed(PhoneGroup.WatchAction.ACTION, pi, "lock"), g.records, pi, now)
        // One at a time: two bodies built from the same set would carry one number, which stops the watch's records
        // (two histories).
        assertEquals(1, g.add(listOf(signed(PhoneGroup.WatchAction.FREEZE, pi))).size)
        assertEquals(1, g.add(listOf(signed(PhoneGroup.WatchAction.REMOVE, deck))).size)
        assertTrue(g.devices.first { it.id == pi }.frozen)
        assertTrue(g.devices.none { it.id == deck })
    }

    /** The root makes a watch an admin (section 10, "Watches"): it may freeze but admits nobody, and removing it takes it out. */
    @Test
    fun addWatch() {
        val root = SoftwareSigner()
        val g = PhoneGroup.create(root, SoftwareSigner().publicKeyDER, t0)
        val watchKey = SoftwareSigner()
        val watch = SyncEngine.newID()
        for ((id, os) in listOf("abc" to "wearos", watch.uppercase() to "wearos", watch to "android", g.device to "wearos")) {
            assertFailsWith<PhoneGroup.Failure>("$id $os") { g.addWatch(id, "Watch", os, watchKey.publicKeyDER, root, t0) }
        }
        val (ca, r) = g.addWatch(watch, " My watch ", "wearos", watchKey.publicKeyDER, root, t0.plusSeconds(1))
        assertContentEquals(watchKey.publicKeyDER, CertificateInfo(ca).publicKey)
        assertTrue(r in g.records.records)
        val d = assertNotNull(g.devices.firstOrNull { it.id == watch })
        val key = Records.keyHashOfCert(ca)
        assertEquals("My watch", d.name)
        assertEquals("watch", d.role)
        assertEquals("wearos", d.os)
        assertEquals(Records.HARDWARE, d.store)
        assertContentEquals(key, d.key)
        assertContentEquals(key, d.adminKey)
        assertTrue(d.admin)
        assertEquals(Records.WATCH_POWERS, d.powers)
        assertFalse(g.records.mayHost(watch))

        // A device record the watch signs admits nobody.
        val deck = SyncEngine.newID()
        val deckCert = GroupCertificates.member(deck, SoftwareSigner().publicKeyDER, ca, watchKey, t0)
        g.add(listOf(g.records.sign(V2.device(deck, "deck", "member", Records.keyHashOfCert(deckCert), watchKey, t0.plusSeconds(1)), watchKey, ca)))
        assertTrue(g.devices.none { it.id == deck })
        assertNotNull(g.records.refused(listOf(deckCert, ca)))

        g.revoke(watch, root, t0.plusSeconds(2))
        assertTrue(g.devices.none { it.id == watch })
        assertTrue(g.records.isRevoked(key))
    }

    @Test
    fun makeAdmin() {
        val root = SoftwareSigner()
        val g = PhoneGroup.create(root, SoftwareSigner().publicKeyDER, t0)
        val pi = SyncEngine.newID()
        val piKey = Records.keyHashOfCert(GroupCertificates.member(pi, SoftwareSigner().publicKeyDER, g.groupCA, root, t0))
        g.record(pi, "pi", "member", piKey, root, t0, caps = Records.CAPS)
        val adminKey = SoftwareSigner()
        g.setKeyLevel(Records.LEVEL_FILES, root, t0)
        // A computer whose keys sit in a file, or that does not say, needs
        // the user's consent; one with hardware keys does not.
        assertFailsWith<PhoneGroup.FileKey> { g.makeAdmin(pi, adminKey.publicKeyDER, root, t0.plusSeconds(1)) }
        assertFailsWith<PhoneGroup.FileKey> { g.makeAdmin(pi, adminKey.publicKeyDER, root, t0.plusSeconds(1), keyStore = Records.FILE) }
        // A rootless install never, even with the consent (D-79).
        assertFailsWith<PhoneGroup.Rootless> {
            g.makeAdmin(pi, adminKey.publicKeyDER, root, t0.plusSeconds(1), keyStore = Records.ROOTLESS, allowFileKey = true)
        }
        assertEquals(Records.ROOTLESS, Records.storeOf(Records.ROOTLESS, "member"))
        assertEquals(Records.FILE, g.devices.first { it.id == pi }.store)
        val (ca, r) = g.makeAdmin(pi, adminKey.publicKeyDER, root, t0.plusSeconds(1), allowFileKey = true)
        assertContentEquals(adminKey.publicKeyDER, CertificateInfo(ca).publicKey)
        val d = assertNotNull(g.devices.firstOrNull { it.id == pi })
        assertTrue(d.admin)
        assertEquals(Records.FILE, d.store)
        assertEquals(Records.HARDWARE, g.devices.first { it.id == g.device }.store)
        assertContentEquals(Records.keyHashOfCert(ca), d.adminKey)
        assertContentEquals(piKey, d.key)
        assertTrue(r in g.records.records)
        assertContentEquals(ca, g.computerAdminCA(adminKey.publicKeyDER))
        assertNull(g.computerAdminCA(SoftwareSigner().publicKeyDER))
        assertFailsWith<PhoneGroup.Failure> { g.makeAdmin(g.device, adminKey.publicKeyDER, root, t0, allowFileKey = true) }
        assertFailsWith<PhoneGroup.Failure> { g.makeAdmin(SyncEngine.newID(), adminKey.publicKeyDER, root, t0, allowFileKey = true) }

        // The admin computer admits the deck; removing the computer keeps it.
        val deck = SyncEngine.newID()
        val deckCert = GroupCertificates.member(deck, SoftwareSigner().publicKeyDER, ca, adminKey, t0)
        g.add(listOf(g.records.sign(V2.device(deck, "deck", "member", Records.keyHashOfCert(deckCert), adminKey, t0), adminKey, ca)))
        assertTrue(g.devices.any { it.id == deck })
        g.revoke(pi, root, t0)
        assertEquals(setOf(g.device, deck), g.devices.map { it.id }.toSet())
        assertNull(g.computerAdmins[pi])
        assertNull(g.computerAdminCA(adminKey.publicKeyDER))
    }

    /** Writes swift-renewal.json, swift-admin.json and swift-computer-admin.json for internal/group's TestSwift tests. */
    @Test
    fun forGo() {
        val dir = Interop.out ?: return
        val ca = SoftwareSigner()
        val g = PhoneGroup.create(ca, SoftwareSigner().publicKeyDER, t0)
        val key = SoftwareSigner()
        val pc = SyncEngine.newID()
        val cert = GroupCertificates.member(pc, key.publicKeyDER, g.groupCA, ca, t0)
        val renewed = assertNotNull(GroupCertificates.renewal(cert, g.groupCA, ca, later))
        val adminKey = SoftwareSigner()
        val adminCA = GroupCertificates.adminCA(SyncEngine.newID(), adminKey.publicKeyDER, g.groupCA, ca)
        val byAdmin = assertNotNull(GroupCertificates.renewal(listOf(cert), listOf(g.groupCA), adminKey, later, adminCA))
        File(dir, "swift-renewal.json").writeBytes(
            Wire.encode(
                Wire.obj(
                    "device" to Wire.str(pc), "group_ca" to Wire.bytes(g.groupCA), "key" to Wire.bytes(key.keyPair.private.encoded),
                    "cert" to Wire.bytes(cert), "renewed" to Wire.bytes(renewed), "admin_ca" to Wire.bytes(adminCA),
                    "admin_renewed" to Wire.bytes(byAdmin),
                ),
            ),
        )

        // An admin phone and the computer it admitted.
        val adminDevice = SyncEngine.newID()
        val deskKey = SoftwareSigner()
        val desk = SyncEngine.newID()
        val deskCert = GroupCertificates.member(desk, deskKey.publicKeyDER, adminCA, adminKey, t0)
        val set = RecordSet()
        set.signed(V2.device(adminDevice, "Second", "phone", Records.keyHash(adminKey.publicKeyDER), ca, t0, Records.keyHashOfCert(adminCA)), ca, g.groupCA)
        set.signed(V2.device(desk, "Desk", "member", Records.keyHashOfCert(deskCert), adminKey, t0), adminKey, g.groupCA, adminCA)
        val records = set.records
        File(dir, "swift-admin.json").writeBytes(
            Wire.encode(
                Wire.obj(
                    "group_ca" to Wire.bytes(g.groupCA), "admin_ca" to Wire.bytes(adminCA), "cert" to Wire.bytes(deskCert),
                    "key" to Wire.bytes(deskKey.keyPair.private.encoded), "device" to Wire.str(desk),
                    "records" to JsonArray(records.map { it.toJson() }),
                    "devices" to JsonArray(set.devices.map { Wire.str(it.id)!! }), "digest" to Wire.str(set.digest),
                ),
            ),
        )

        // The root makes a computer an admin.
        g.record(pc, "pi", "member", Records.keyHashOfCert(cert), ca, t0, caps = Records.CAPS)
        val computerKey = SoftwareSigner()
        g.setKeyLevel(Records.LEVEL_FILES, ca, t0)
        val (computerCA, _) = g.makeAdmin(pc, computerKey.publicKeyDER, ca, t0.plusSeconds(1), allowFileKey = true)
        File(dir, "swift-computer-admin.json").writeBytes(
            Wire.encode(
                Wire.obj(
                    "group_ca" to Wire.bytes(g.groupCA), "device" to Wire.str(pc), "admin_key" to Wire.bytes(computerKey.publicKeyDER),
                    "admin_ca" to Wire.bytes(computerCA), "records" to JsonArray(g.records.records.map { it.toJson() }),
                ),
            ),
        )
    }
}

/** A self-signed certificate with a P-384 key for the device ID 0123456789abcdef0123456789abcdef. */
private const val P384_CERT =
    "MIIB6DCCAW6gAwIBAgIUAZv1zxaQendV3vrzM9UqL0xFbGQwCgYIKoZIzj0EAwIwKzEpMCcGA1UEAwwgMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwHhcNMjYxMDMxMDgwMTA3WhcNMzYxMDI4MDgwMTA3WjArMSkwJwYDVQQDDCAwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjB2MBAGByqGSM49AgEGBSuBBAAiA2IABGPVHQzOkUL3/eN4mcZqO6tU7B6YS8I21tzGWFeoddh3g8gFJ+lvOeXnWNDs5Kb4ewC4C7xajcObF96dLzHm4iJLndLCPs6Ry8yp+n1Qq2iNjfdEP6DbDovujn61huXGe6NTMFEwHQYDVR0OBBYEFOiZlbxuz4DpfnxiZUCH1Uk1ltN+MB8GA1UdIwQYMBaAFOiZlbxuz4DpfnxiZUCH1Uk1ltN+MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDaAAwZQIxAL+QMr4a6NK+ye/WnoyqP6zSKvX2m36eBB4JLFFWRDXxvuDkkxbOyY1qZTgnAIK79AIwe1vxP94FlJL73T9uTn9I9VolozxxhdFHmsM+uW9t+sFJU14EH1l/ci4PaH7hPKkz"
