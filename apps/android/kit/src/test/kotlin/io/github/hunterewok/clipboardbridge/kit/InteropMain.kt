// SPDX-License-Identifier: AGPL-3.0-only

// The Kotlin twin of clipboardbridge-interop (apps/ios/ClipboardBridgeKit): it
// plays the Android phone against the Go code in tests, with the same
// commands, so Go's TestSwiftMemberAdmitsGoJoiner, TestSwiftMemberAdmitsGoJoinerTLS,
// TestSwiftHubAdmitsInvitedGoJoiner, TestSwiftJoinsComputerRoot and TestSwiftMemberTLS
// run it too. Gradle's
// interopScript task writes a script that starts it.
//
//   admit HOST PORT CODE                 pairing over plain TCP, certificates exchanged in place of TLS
//   admit-tls HOST PORT CODE FINGERPRINT pairing over TLS
//
// print the group CA in base64 on success.
//
//   join-tls HOST PORT CODE
//
// joins a computer's group through the pairing window that `cbb pair`
// opened at HOST:PORT, as a phone with an admin key, and prints the group
// CA and then the admin CA the root issued, each in base64 on a line.
//
//   invite-window SECRET yes|no
//
// opens a remote invitation's pairing window on the loopback address with
// SECRET (base64), as the phone that is the hub does, and prints
// "port N"; for the device that proves it knows the secret it prints
// "fingerprint F" and admits it or not; then it prints the group CA in
// base64 and ends, or fails with the first failed attempt.
//
//   member-tls HOST PORT PEER
//
// prints "key <SubjectPublicKeyInfo, base64>", reads "cert <DER, base64>"
// and "ca <DER, base64>" from standard input, dials the Go member PEER with
// TLS, sends "from swift" (the Swift tool's text, which Go waits for),
// waits for "from go", then for Go's picture "go picture", which it
// fetches, sends its bytes reversed as "phone picture", which Go fetches,
// waits for "done", and prints "ok". Test use only.
//
//   restore-tls HOST PORT KEY CERT GROUP
//
// restores the group of the Go member at HOST:PORT on a new phone with the
// group's recovery key: KEY (its 32 bytes) and CERT (its admin CA, DER),
// both base64, and GROUP, the group's tag, make the sheet's QR code, which
// the tool reads as the app does. It takes the records, checks them,
// claims the group for a new root, sends the claim on a second connection,
// and prints its device ID, then the new root in base64. Test use only.

package io.github.hunterewok.clipboardbridge.kit

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import java.time.Instant
import java.util.Base64
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess

private fun fail(msg: String): Nothing {
    System.err.println("clipboardbridge-interop: $msg")
    exitProcess(1)
}

private fun admit(host: String, port: Int, code: String, fingerprint: String?) {
    val now = Instant.now()
    val caSigner = SoftwareSigner()
    val memberKey = SoftwareSigner()
    val group = PhoneGroup.create(caSigner, memberKey.publicKeyDER, now)
    val t: FrameTransport
    val joinerCert: ByteArray
    val sid: ByteArray
    if (fingerprint != null) {
        val tls = TLSTransport.dial(host, port, Pairing.ALPN, memberKey.keyPair.private, listOf(group.memberCert)) {
            Pairing.fingerprint(it[0]) == fingerprint
        }
        t = tls
        joinerCert = tls.peerCertificate ?: fail("no peer certificate")
        sid = tls.exportKeyingMaterial(Pairing.EXPORTER_LABEL, 32)
    } else {
        // In place of the TLS handshake: the member's certificate, then the joiner's; the session ID is fixed.
        val s = Socket(host, port)
        val out = DataOutputStream(s.getOutputStream())
        val input = DataInputStream(s.getInputStream())
        out.writeInt(group.memberCert.size)
        out.write(group.memberCert)
        out.flush()
        joinerCert = ByteArray(input.readInt()).also { input.readFully(it) }
        t = StreamTransport(input, out, s::close)
        sid = ByteArray(32)
    }
    val admitted = try {
        group.admit(t, code, joinerCert, sid, caSigner, now)
    } finally {
        t.close()
    }
    if (!admitted.confirmed || group.computers.map { it.device } != listOf(admitted.device)) fail("the joiner did not confirm")
    println(Base64.getEncoder().encodeToString(group.groupCA))
}

private fun joinTLS(host: String, port: Int, code: String) {
    val member = SoftwareSigner()
    val admin = SoftwareSigner()
    val cert = GroupCertificates.selfSigned(SyncEngine.newID(), member)
    // The window's certificate is checked by the code's exchange, not here.
    val tls = TLSTransport.dial(host, port, Pairing.ALPN, member.keyPair.private, listOf(cert)) { it.isNotEmpty() }
    val joined = try {
        val leaf = tls.peerCertificate ?: fail("no peer certificate")
        val sid = tls.exportKeyingMaterial(Pairing.EXPORTER_LABEL, 32)
        val info = Pairing.Info("android", "android", admin.publicKeyDER)
        PairingJoiner.join(tls, code, info, leaf, cert, sid, Instant.now()) { PhoneGroup.joined(it) }
    } finally {
        tls.close()
    }
    val adminCA = joined.welcome.adminCA ?: fail("the welcome carries no admin CA")
    println(Base64.getEncoder().encodeToString(joined.welcome.groupCA))
    println(Base64.getEncoder().encodeToString(adminCA))
}

private fun memberTLS(host: String, port: Int, peer: String) {
    val key = SoftwareSigner()
    println("key ${Base64.getEncoder().encodeToString(key.publicKeyDER)}")
    System.out.flush()
    fun field(name: String): ByteArray {
        val line = readlnOrNull() ?: fail("no $name on standard input")
        if (!line.startsWith("$name ")) fail("no $name on standard input")
        return Base64.getDecoder().decode(line.removePrefix("$name "))
    }
    val cert = field("cert")
    val ca = field("ca")
    val me = CertificateInfo(cert).commonName ?: fail("no device ID")
    val tls = TLSTransport.dial(host, port, Member.ALPN, key.keyPair.private, listOf(cert)) {
        runCatching { GroupCertificates.verifyMember(it[0], ca, Instant.now()) }.getOrNull() == peer
    }
    val changes = LinkedBlockingQueue<Member.Event>()
    val store = MemoryContent()
    val node = MemberNode(SyncEngine(me, HybridClock()), "Android", onChange = { changes.add(it) }, content = store)
    val serving = Thread { node.serve(tls, peer) }.apply { start() }
    val deadline = System.nanoTime() + 15_000_000_000L
    while (node.peers == 0) {
        if (System.nanoTime() > deadline) fail("no hello within 15 s")
        Thread.sleep(50)
    }
    node.send("from swift", Member.Kind.TEXT) // the text Go's test waits for
    fun await(text: String): Member.Event {
        while (true) {
            val left = deadline - System.nanoTime()
            val e = changes.poll(maxOf(left, 0), TimeUnit.NANOSECONDS) ?: fail("no \"$text\" within 15 s")
            if (e.text == text) return e
        }
    }
    await("from go")
    val picture = await("go picture")
    val part = picture.media?.parts?.singleOrNull() ?: fail("Go's picture has no part")
    val png = try {
        Content.bytes(node, picture, part)
    } catch (e: Exception) {
        fail("fetching Go's picture: $e")
    }
    node.send("phone picture", Member.Kind.TEXT, media = Content.manifest(store, listOf("image/png" to png.reversedArray())))
    await("done")
    println("ok")
    System.out.flush()
    node.closeAll()
    serving.join()
}

private fun restoreTLS(host: String, port: Int, key: ByteArray, cert: ByteArray, tag: String) {
    val qr = Core.recoverySheet(key, cert, tag).qr
    val sheet = (Core.readRecoverySheet(qr) as? Core.SheetReading.Key)?.key ?: fail("the sheet's QR code does not read")
    val memberKey = SoftwareSigner()
    val now = Instant.now()
    val r = Restore(sheet, memberKey.publicKeyDER, now)
    // The handshake takes any certificate; Restore.group checks the computer's against the records.
    fun dial() = TLSTransport.dial(host, port, Member.ALPN, memberKey.keyPair.private, r.chain) { true }
    val g = r.group(Restore.exchange(dial(), "Android", "android", now), now)
    val newRoot = GroupCertificates.groupCA(SoftwareSigner(), now, pathLength = 1)
    val claim = r.claim(g, newRoot, now)
    Restore.exchange(dial(), "Android", "android", Instant.now(), send = listOf(claim))
    println(r.device)
    println(Base64.getEncoder().encodeToString(newRoot))
    System.out.flush()
}

private fun inviteWindow(secret: ByteArray, yes: Boolean) {
    val now = Instant.now()
    val caSigner = SoftwareSigner()
    val memberKey = SoftwareSigner()
    val group = PhoneGroup.create(caSigner, memberKey.publicKeyDER, now)
    val ended = LinkedBlockingQueue<Result<PairingMember.Admitted>>()
    val invitation = PairingMember.Invitation(secret) { req ->
        println("fingerprint ${req.fingerprint}")
        System.out.flush()
        yes
    }
    val window = InvitationWindow(
        memberKey.keyPair.private, group.memberCert, now.plusSeconds(60),
        admit = { t, joinerCert, sid -> group.admit(t, "", joinerCert, sid, caSigner, Instant.now(), invitation = invitation) },
        onEnd = { ended.add(it) },
        onError = { ended.add(Result.failure(it)) },
    )
    println("port ${window.port}")
    System.out.flush()
    val result = ended.poll(30, TimeUnit.SECONDS) ?: fail("no attempt within 30 s")
    val admitted = result.getOrElse { fail("$it") }
    if (!admitted.confirmed || group.computers.map { it.device } != listOf(admitted.device)) fail("the joiner did not confirm")
    println(Base64.getEncoder().encodeToString(group.groupCA))
}

fun main(args: Array<String>) {
    try {
        val port = args.getOrNull(2)?.toIntOrNull()
        when {
            args.size == 4 && args[0] == "member-tls" && port != null -> memberTLS(args[1], port, args[3])
            args.size == 4 && args[0] == "admit" && port != null -> admit(args[1], port, args[3], null)
            args.size == 5 && args[0] == "admit-tls" && port != null -> admit(args[1], port, args[3], args[4])
            args.size == 4 && args[0] == "join-tls" && port != null -> joinTLS(args[1], port, args[3])
            args.size == 6 && args[0] == "restore-tls" && port != null ->
                restoreTLS(args[1], port, Base64.getDecoder().decode(args[3]), Base64.getDecoder().decode(args[4]), args[5])
            args.size == 3 && args[0] == "invite-window" -> inviteWindow(Base64.getDecoder().decode(args[1]), args[2] == "yes")
            else -> {
                System.err.println("usage: clipboardbridge-interop admit HOST PORT CODE | admit-tls HOST PORT CODE FINGERPRINT | join-tls HOST PORT CODE | invite-window SECRET yes|no | member-tls HOST PORT PEER | restore-tls HOST PORT KEY CERT GROUP")
                exitProcess(2)
            }
        }
    } catch (e: Exception) {
        fail("$e")
    }
    exitProcess(0)
}
