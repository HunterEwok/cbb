// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The phones' tunnel in Rust as the app wraps it: a hub and a client on the loopback address, a remote invitation, a
 * refused request and a relay link that reports why it is not connected. The tunnel's path itself is tested against Go's
 * hub, forwarder and relay in Go (internal/tunnel, TestRustPhone*).
 */
class RustTunnelTest {
    private val phone = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    private val hubID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)

    @Test
    fun hubAndClient() {
        val hubKey = RustTunnel.newKey()
        val clientKey = RustTunnel.newKey()
        assertEquals(32, hubKey.size)
        assertNotEquals(b64(hubKey), b64(clientKey))
        val psk = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val clients = JsonArray(
            listOf(
                JsonObject(mapOf("device" to JsonPrimitive(phone), "key" to JsonPrimitive(b64(RustTunnel.publicKey(clientKey))), "psk" to JsonPrimitive(b64(psk)))),
            ),
        ).toString()
        ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { member ->
            val hub = RustTunnel.startHub(hubKey, hubID, member.localPort, "", clients)
            try {
                assertEquals("{}", hub.status(), "no forwarder before the registration")
                hub.setClients(clients)
                val t = RustTunnel.start(clientKey, psk, RustTunnel.publicKey(hubKey), phone, hubID, "127.0.0.1:${hub.udpPort()}", "", "")
                try {
                    assertNotEquals(0, t.port)
                    Socket(InetAddress.getLoopbackAddress(), t.port).close()
                    t.setEndpoint("127.0.0.1:${hub.udpPort()}")
                } finally {
                    t.close()
                }
                val g = hub.invite("0123456789abcdef", "[\"192.0.2.1:3276\"]", 600, member.localPort)
                assertTrue(g.text.startsWith("cbb://invite#"), g.text)
                assertEquals(16, g.secret.size)
                assertTrue(g.expires > Instant.now().epochSecond)
                g.admitted()
                g.close()
            } finally {
                hub.close()
            }
        }
    }

    /** The hub's settings the app passes on: AmneziaWG, VLESS, the records, the project's ways and the forwarder. */
    @Test
    fun hubSettings() {
        val obfuscation = RustTunnel.newObfuscation()
        assertTrue(obfuscation.startsWith("{"), obfuscation)
        val vlessID = RustTunnel.newVLESSID()
        assertTrue(vlessID.isNotEmpty())
        val now = Instant.now()
        val root = SoftwareSigner()
        val groupCA = GroupCertificates.groupCA(root, now, 1)
        val leaf = GroupCertificates.member(hubID, root.publicKeyDER, groupCA, root, now)
        ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { member ->
            val hub = RustTunnel.startHub(RustTunnel.newKey(), hubID, member.localPort, obfuscation, "[]")
            try {
                // The records go to the forwarder, so they wait for the registration.
                assertFailsWith<RustTunnel.Failure> { hub.setRecords("[]") }
                hub.setProjectWays("[]")
                val vless = """{"transport":"xhttp","endpoint":"192.0.2.1:443","server_name":"example.org","path":"/cbb","id":"$vlessID"}"""
                val g = hub.invite("0123456789abcdef", "[\"127.0.0.1:${hub.udpPort()}\"]", 600, member.localPort, vless)
                try {
                    assertIs<Core.InviteReading.Read>(Core.readInvite(g.text))
                } finally {
                    g.close()
                }
                // The registration goes on in the background, here toward a port where no forwarder listens.
                hub.register("127.0.0.1:9", b64(ByteArray(32)), "[\"${b64(leaf)}\",\"${b64(groupCA)}\"]", root::signDigest, "[]", vlessID)
                hub.setRecords("[]")
                assertFailsWith<RustTunnel.Failure> { hub.register("127.0.0.1:9", "pin", "[]", root::signDigest, "[]", "") }
            } finally {
                hub.close()
            }
        }
    }

    @Test
    fun refusals() {
        val e = assertFailsWith<RustTunnel.Failure> { RustTunnel.publicKey(ByteArray(5)) }
        assertTrue(e.toString().startsWith("tunnel: "), e.toString())
        assertFailsWith<RustTunnel.Failure> { RustTunnel.startHub(ByteArray(32), hubID, 0, "", "") }
    }

    @Test
    fun relayReportsWhyItIsNotConnected() {
        val now = Instant.now()
        val root = SoftwareSigner()
        val key = SoftwareSigner()
        val groupCA = GroupCertificates.groupCA(root, now, 1)
        val leaf = GroupCertificates.member(phone, key.publicKeyDER, groupCA, root, now)
        val states = CopyOnWriteArrayList<String>()
        val events = object : RustTunnel.RelayEvents {
            override fun dial(peer: String, port: Int) {}
            override fun calling(peer: String, localPort: Int) {}
            override fun wanted(peer: String): Boolean = true
            override fun changed(state: String) {
                states += state
            }
        }
        val link = RustTunnel.startRelay(
            RustTunnel.newKey(), phone, "127.0.0.1:9", b64(ByteArray(32)), "[\"${b64(leaf)}\",\"${b64(groupCA)}\"]",
            key::signDigest, "", 9, events,
        )
        try {
            val deadline = System.nanoTime() + 10_000_000_000L
            while (states.isEmpty() && System.nanoTime() < deadline) Thread.sleep(50)
            val report = Json.parseToJsonElement(assertNotNull(states.firstOrNull(), "no report")) as JsonObject
            assertNull(report["type"], "the app gets the report as the hub gave it")
            assertNotNull(report["error"], report.toString())
            link.setRecords("[]")
            link.setCredentials(ByteArray(0), key::signDigest, "", "[]", "{}")
        } finally {
            link.close()
        }
    }
}
