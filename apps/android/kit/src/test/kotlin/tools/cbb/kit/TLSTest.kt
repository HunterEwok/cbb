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
    /** Two members in the Rust core sync over its member TLS: each sees the other's chain, and a copy each way arrives. */
    @Test
    fun membersSyncOverTLS() = CoreGroup().use { t ->
        val (a, b) = t.phones
        t.connect(1, 0)
        assertTrue(b.peer(a.device).chain.first().contentEquals(t.g.memberCert))
        a.member.copy("over TLS")
        b.copy("over TLS")
        b.member.copy("and back")
        a.copy("and back")
    }

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
                    PairingJoiner.accept(it, "112233", Pairing.Info("Pixel", "android", adminKey.publicKeyDER).proving(sid, adminKey), it.peerChain[0], joinerCert, sid, now) {}
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

}
