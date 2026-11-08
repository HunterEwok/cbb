// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Making a group, joining it and admitting a device through the Rust core (CorePairing), as the apps do. */
class CorePairingTest {
    private val top: File = createTempDirectory("cbb-core-pairing").toFile()
    private val members = mutableListOf<CoreMember>()
    private val pool = Executors.newCachedThreadPool()

    @AfterTest
    fun cleanUp() {
        members.forEach { it.close() }
        pool.shutdownNow()
        top.deleteRecursively()
    }

    /** A root phone: the group the core made with its root key, and its member running. */
    private class Root(val root: SoftwareSigner, val group: PhoneGroup, val member: CoreMember)

    private fun root(): Root {
        val root = SoftwareSigner()
        val key = SoftwareSigner()
        val made = CorePairing.newGroup("Root phone", "android", Records.HARDWARE, root.publicKeyDER, key.publicKeyDER, Core.sealPublic(CoreGroup.SEAL), root::signDigest)
        val g = PhoneGroup.of(made, root = true)
        val m = CoreMember.start(
            CoreMember.Start(File(top, "root").apply { mkdirs() }, "Root phone", "android", "17", "0.6.0", device = g.device, publicKey = key.publicKeyDER,
                seal = CoreGroup.SEAL, cert = g.memberCert, groupCA = g.groupCA, roots = g.trusted),
            key::signDigest,
            events = { },
        )
        members += m
        m.addRecords(g.records.records)
        return Root(root, g, m)
    }

    @Test
    fun newGroupHasTheRootAndItsPhone() {
        val r = root()
        assertTrue(r.group.isRoot)
        assertNull(r.group.adminCA)
        val me = r.group.devices.single()
        assertEquals(r.group.device, me.id)
        assertEquals("phone", me.role)
        // The member certificate comes from the group's root, whose key signed it.
        assertContentEquals(r.root.publicKeyDER, CertificateInfo(r.group.groupCA).publicKey)
    }

    /** A phone listens with its QR code, the root scans it and admits it; with offer, it asks to be an admin, which makeAdmin grants. */
    private fun joinAndAdmit(r: Root, code: String = "", typed: String? = null, offer: Boolean = false, makeAdmin: Boolean = false):
        Pair<Result<CorePairing.Group>, Result<CorePairing.Admitted>> {
        val listener = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val key = SoftwareSigner()
        val admin = if (offer) SoftwareSigner() else null
        val joining = CorePairing.Joining(
            "Second phone", "android", key.publicKeyDER, Core.sealPublic(CoreGroup.SEAL), listOf("127.0.0.1:${listener.localPort}"), key::signDigest,
            adminPublic = admin?.publicKeyDER, signAdmin = admin?.let { it::signDigest }, code = code,
        )
        val saved = CopyOnWriteArrayList<CorePairing.Group>()
        val joined = pool.submit<CorePairing.Group> {
            listener.use { l ->
                l.soTimeout = 15_000
                l.accept().use { s ->
                    s.soTimeout = 15_000
                    joining.attempt(s) { saved.add(it) }
                }
            }
        }
        // The QR code a user scanned; a test that types another code changes it there.
        val qr = typed?.let { joining.qr.replace("code=${joining.code}", "code=$it") } ?: joining.qr
        val admitted = runCatching {
            CorePairing.Admitting(r.member, qr, r.root.publicKeyDER, null, makeAdmin, r.root::signDigest).use { a ->
                val (host, port) = a.addrs.single().split(':')
                Socket(host, port.toInt()).use { s ->
                    s.soTimeout = 15_000
                    a.admit(s)
                }
            }
        }
        val j = runCatching { joined.get(20, TimeUnit.SECONDS) }
        joining.close()
        j.getOrNull()?.let { assertEquals(it.device, saved.single().device) }
        return j to admitted
    }

    @Test
    fun rootAdmitsAPhoneThatListens() {
        val r = root()
        val (j, a) = joinAndAdmit(r)
        val group = j.getOrThrow()
        val admitted = a.getOrThrow()
        assertEquals(group.device, admitted.device)
        assertEquals("Second phone", admitted.name)
        assertEquals("phone", admitted.role)
        assertTrue(admitted.confirmed, "the joiner said it stored its identity")
        assertEquals(false, admitted.admin)
        val p = PhoneGroup.of(group, root = false)
        assertContentEquals(r.group.groupCA, p.groupCA)
        assertEquals(false, p.isRoot)
        assertNull(p.adminCA)
        // The joiner's certificate names it and comes from the group's root.
        assertEquals(group.device, CertificateInfo(group.cert).commonName)
        // Its record is in the root's member at once, and in the records the joiner took.
        val rs = RecordSet.fromFile(r.group.groupCA, ByteArray(0)).also { it.addAll(r.member.records(), r.group.groupCA) }
        assertTrue(rs.devices.any { it.id == group.device && it.role == "phone" }, "the root's records list the new phone")
        assertTrue(p.devices.any { it.id == r.group.device }, "the joiner's records list the root phone")
    }

    @Test
    fun rootMakesAPhoneThatAsksAnAdmin() {
        val r = root()
        val (j, a) = joinAndAdmit(r, offer = true, makeAdmin = true)
        val group = j.getOrThrow()
        assertTrue(a.getOrThrow().admin)
        val ca = assertNotNull(group.adminCA, "the joiner got its admin CA")
        val p = PhoneGroup.of(group, root = false)
        assertTrue(p.isAdmin)
        assertContentEquals(ca, p.adminCA)
    }

    /** A phone that asks to be an admin joins only where the root chose to make one (docs/protocol.md, section 6). */
    @Test
    fun aPhoneThatAsksIsRefusedWithoutMakeAdmin() {
        val r = root()
        val (j, a) = joinAndAdmit(r, offer = true, makeAdmin = false)
        val e = assertFailsWith<CorePairing.Failure> { a.getOrThrow() }
        assertTrue(e.message!!.contains("add it as an admin"), e.message)
        assertTrue(j.isFailure, "the phone did not join")
    }

    @Test
    fun aWrongCodeFailsBothSides() {
        val r = root()
        val (j, a) = joinAndAdmit(r, code = "123456", typed = "654321")
        val e = assertFailsWith<CorePairing.Failure> { a.getOrThrow() }
        assertTrue(e.wrongCode, "the admin's side says the code was wrong: ${e.message}")
        assertTrue(j.isFailure, "the joiner did not join")
        // Nothing reached the records.
        val rs = RecordSet.fromFile(r.group.groupCA, ByteArray(0)).also { it.addAll(r.member.records(), r.group.groupCA) }
        assertEquals(listOf(r.group.device), rs.devices.map { it.id })
    }
}
