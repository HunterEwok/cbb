// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** TLS 1.3 with Conscrypt between two kits: pairing as a phone joining a phone does it, and a member connection. */
class TLSTest {
    private val now = Instant.now()

    @Test
    fun phoneJoinsOverTLS() {
        val rootKey = SoftwareSigner()
        val memberKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, memberKey.publicKeyDER, now)

        // The joining phone listens with a self-signed certificate; its QR code carries the fingerprint.
        val joinerDevice = SyncEngine.newID()
        val joinerKey = SoftwareSigner()
        val joinerCert = GroupCertificates.selfSigned(joinerDevice, joinerKey)
        val fp = Pairing.fingerprint(joinerCert)
        val adminKey = SoftwareSigner()
        val listener = TLSListener(0, Pairing.ALPN, joinerKey.keyPair.private, listOf(joinerCert)) { it.isNotEmpty() }
        try {
            val joined = Background {
                val t = listener.accept()
                assertTrue(t.peerChain.isNotEmpty())
                val sid = t.exportKeyingMaterial(Pairing.EXPORTER_LABEL, 32)
                t.use {
                    PairingJoiner.accept(it, "112233", Pairing.Info("Pixel", "android", adminKey.publicKeyDER), it.peerChain[0], joinerCert, sid, now) {}
                } to sid
            }
            val t = TLSTransport.dial("127.0.0.1", listener.port, Pairing.ALPN, memberKey.keyPair.private, listOf(root.memberCert)) {
                Pairing.fingerprint(it[0]) == fp
            }
            val sid = t.exportKeyingMaterial(Pairing.EXPORTER_LABEL, 32)
            val admitted = t.use { root.admit(it, "112233", assertNotNull(it.peerCertificate), sid, rootKey, now) }
            val (j, joinerSid) = joined.join()
            assertContentEquals(sid, joinerSid, "both ends export the same session ID")
            assertEquals(joinerDevice, admitted.device)
            assertNotNull(j.welcome.adminCA)
            assertEquals("phone", root.devices.first { it.id == joinerDevice }.role)
        } finally {
            listener.stop()
        }
    }

    @Test
    fun refusals() {
        val key = SoftwareSigner()
        val cert = GroupCertificates.selfSigned(SyncEngine.newID(), key)
        val listener = TLSListener(0, Pairing.ALPN, key.keyPair.private, listOf(cert)) { true }
        try {
            // A fingerprint that does not match: the dialler refuses.
            val server = Background { runCatching { listener.accept() } }
            assertFailsWith<TLSTransport.Failure> {
                TLSTransport.dial("127.0.0.1", listener.port, Pairing.ALPN, key.keyPair.private, listOf(cert)) { false }
            }
            server.join()
            // Another protocol: the listener's side ends the handshake.
            val server2 = Background { runCatching { listener.accept() } }
            assertFailsWith<TLSTransport.Failure> {
                TLSTransport.dial("127.0.0.1", listener.port, Member.ALPN, key.keyPair.private, listOf(cert)) { true }.close()
            }
            assertTrue(server2.join().isFailure)
        } finally {
            listener.stop()
        }
    }

    @Test
    fun membersSyncOverTLS() {
        val caKey = SoftwareSigner()
        val ca = GroupCertificates.groupCA(caKey, now, pathLength = 1)
        fun member(): Triple<String, SoftwareSigner, ByteArray> {
            val id = SyncEngine.newID()
            val k = SoftwareSigner()
            return Triple(id, k, GroupCertificates.member(id, k.publicKeyDER, ca, caKey, now))
        }
        val (aID, aKey, aCert) = member()
        val (bID, bKey, bCert) = member()
        val listener = TLSListener(0, Member.ALPN, bKey.keyPair.private, listOf(bCert)) {
            runCatching { GroupCertificates.verifyMember(it, ca, now) }.getOrNull() == aID
        }
        val got = java.util.concurrent.LinkedBlockingQueue<String>()
        val b = MemberNode(SyncEngine(bID, HybridClock()), "B", onChange = { got.add(it.text) })
        val a = MemberNode(SyncEngine(aID, HybridClock()), "A")
        try {
            val serving = Background { b.serve(listener.accept()) }
            val t = TLSTransport.dial("127.0.0.1", listener.port, Member.ALPN, aKey.keyPair.private, listOf(aCert)) {
                runCatching { GroupCertificates.verifyMember(it, ca, now) }.getOrNull() == bID
            }
            val dialled = Background { a.serve(t) }
            waitUntil { a.peers == 1 }
            a.send("over TLS", Member.Kind.TEXT)
            assertEquals("over TLS", got.poll(10, java.util.concurrent.TimeUnit.SECONDS))
            a.closeAll()
            dialled.join()
            serving.join()
        } finally {
            listener.stop()
        }
    }
}
