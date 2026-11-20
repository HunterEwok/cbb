// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CommandsTest {
    /** A command goes to its receiver, whose app answers; one for a device not connected, with no hub between, goes nowhere. */
    @Test
    fun commandRoundTrip() = CoreGroup().use { t ->
        val (a, b) = t.phones
        t.connect(1, 0)
        val c = t.g.modeCommand(b.device, "own", t.ca, java.time.Instant.now())
        val answering = Thread {
            val e = b.next("the command") { it as? CoreMember.Event.Command }
            b.member.answer(e.token, Member.CommandResult("", "refused", "not now"))
        }.apply { start() }
        val r = a.member.command(c)
        answering.join()
        assertEquals(Commands.idOf(c), r.id)
        assertEquals("refused", r.status)
        assertEquals("not now", r.reason)
        val other = t.g.modeCommand(SyncEngine.newID(), "own", t.ca, java.time.Instant.now())
        assertFailsWith<Core.Refusal> { a.member.command(other) }
    }

    /** A phone not connected to a command's receiver sends it to the admin phone that is, the hub, which passes it on once; the result comes back the same way. */
    @Test
    fun commandPassedOn() = CoreGroup(3).use { t ->
        val (hub, a, b) = t.phones
        t.connect(1, 0)
        t.connect(2, 0)
        val c = t.g.modeCommand(b.device, "own", t.ca, java.time.Instant.now())
        val answering = Thread {
            val e = b.next("the command") { it as? CoreMember.Event.Command }
            assertEquals(hub.device, e.from)
            b.member.answer(e.token, Member.CommandResult("", "done"))
        }.apply { start() }
        val r = a.member.command(c)
        answering.join()
        assertEquals("done", r.status)
        assertEquals(b.device, r.by)
        assertTrue(hub.all { it as? CoreMember.Event.Command }.isEmpty(), "the hub does not take it itself")
        // Not passed on again, not even after its result went back.
        assertFailsWith<Core.Refusal> { a.member.command(c, 1_000) }
        assertEquals(1, b.all { it as? CoreMember.Event.Command }.size)
    }

    private val now = Instant.now()
    private val pc = "00112233445566778899aabbccddeeff"

    @Test
    fun modeCommand() {
        val root = SoftwareSigner()
        val ca = GroupCertificates.groupCA(root, now, pathLength = 1)
        val c = Commands.mode(pc, "own", GroupCertificates.tag(ca), "0123456789abcdef0123456789abcdef", now, root)
        val o = Wire.parse(c.body)!!
        assertEquals("mode", o.optString("type"))
        assertEquals(pc, o.optString("to"))
        assertEquals(Commands.LIFETIME_MS, o.optLong("expires_ms")!! - o.optLong("time_ms")!!)
        assertEquals(32, Commands.idOf(c)!!.length)
        assertNull(c.chain)
        assertFailsWith<IllegalArgumentException> { Commands.mode(pc, "everything", "tag", "by", now, root) }
    }

    /** A phone group signs a mode command with its root key, for its own group. */
    @Test
    fun phoneGroupModeCommand() {
        val rootKey = SoftwareSigner()
        val g = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, now)
        val c = g.modeCommand(pc, "receive", rootKey, now)
        val o = Wire.parse(c.body)!!
        assertEquals(g.tag, o.optString("group"))
        assertEquals(g.device, o.optString("by"))
        assertEquals("receive", o.optString("mode"))
        assertNull(c.chain)
    }

    /** A phone group signs a paste command with its root key, its way and kind in the body. */
    @Test
    fun phoneGroupPasteCommand() {
        val rootKey = SoftwareSigner()
        val g = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, now)
        val c = g.pasteCommand(pc, "ls", "type", enter = true, secret = true, caSigner = rootKey, now = now)
        val o = Wire.parse(c.body)!!
        assertEquals("paste", o.optString("type"))
        assertEquals(g.tag, o.optString("group"))
        assertEquals("type", o.optString("mode"))
        assertEquals("secret", o.optString("kind"))
        assertEquals("ls", o.optString("text"))
    }

    /**
     * A phone group signs a paste of a copy of images or files with its root
     * key, and the device it names takes it.
     */
    @Test
    fun phoneGroupPasteCopyCommand() {
        val rootKey = SoftwareSigner()
        val g = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, now)
        val copy = "00112233445566778899aabbccddeeff"
        val b = Commands.verify(g.pasteCopyCommand(pc, copy, enter = true, caSigner = rootKey, now = now), g.records, pc, now.toEpochMilli())
        assertEquals("paste", b.type)
        assertEquals("paste", b.mode)
        assertEquals("media", b.kind)
        assertEquals(copy, b.text)
        assertEquals(true, b.enter)
    }

    /** A hub command carries the forwarder and the clients; a result carries the new hub's offer. */
    @Test
    fun hubCommand() {
        val root = SoftwareSigner()
        val client = PhoneHub.Client("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val c = Commands.hub(pc, "203.0.113.9:8764" to "AAAA", emptyList(), listOf(client), "tag", "by", now, root)
        val o = Wire.parse(c.body)!!
        assertEquals("hub", o.optString("type"))
        val order = o.optObject("hub")!!
        assertEquals("203.0.113.9:8764", order.optObject("forwarder")!!.optString("endpoint"))
        assertEquals(1, order.optArray("clients")!!.size)
        assertFailsWith<IllegalArgumentException> { Commands.hub(pc, null, emptyList(), listOf(client), "tag", "by", now, root) }
        val r = Member.decode(
            """{"t":"result","result":{"id":"ab","status":"done","tunnel":{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","endpoints":["203.0.113.9:8764"]}}}""".toByteArray(),
        ) as Member.Message.Result
        assertEquals(listOf("203.0.113.9:8764"), r.result.tunnel?.endpoints)
        val hub = PhoneHub(ByteArray(32) { 9 }, listOf(client))
        val moved = hub.movedOffer(client.device, pc, r.result.tunnel!!)!!
        assertEquals(pc, moved.hub)
        assertTrue(moved.moved)
        assertEquals(client.psk.toList(), moved.psk.toList())
        assertNull(hub.movedOffer(pc, pc, r.result.tunnel!!))
        val back = Member.decode(Member.encode(Member.Message.Tunnel(moved)).let { it.copyOfRange(4, it.size) }) as Member.Message.Tunnel
        assertEquals(moved, back.offer)
    }

    /** A command and its result through the frames, as Go sends and reads them. */
    @Test
    fun messages() {
        val c = Member.Record("{}".toByteArray(), byteArrayOf(1, 2), listOf(byteArrayOf(3)))
        for (m in listOf(Member.Message.Command(c), Member.Message.Result(Member.CommandResult("ab", "refused", "why")))) {
            val e = Member.encode(m)
            assertEquals(m, Member.decode(e.copyOfRange(4, e.size)))
        }
        val h = Member.decode("""{"t":"hello","role":"member","hello":{"wall_ms":1,"mode":"receive"}}""".toByteArray()) as Member.Message.Hello
        assertEquals("receive", h.hello.mode)
        val odd = Member.decode("""{"t":"hello","role":"member","hello":{"wall_ms":1,"mode":"everything"}}""".toByteArray()) as Member.Message.Hello
        assertNull(odd.hello.mode)
    }

    /** A paste command carries its way, Enter, kind and text, within the limits; paste-off carries nothing. */
    @Test
    fun pasteCommand() {
        val root = SoftwareSigner()
        val ca = GroupCertificates.groupCA(root, now, pathLength = 1)
        val c = Commands.paste(pc, "ls <dir>", enter = true, kind = "secret", group = GroupCertificates.tag(ca), by = pc, now = now, signer = root)
        val o = Wire.parse(c.body)!!
        assertEquals("paste", o.optString("type"))
        assertEquals("paste", o.optString("mode"))
        assertEquals("ls <dir>", o.optString("text"))
        assertEquals("secret", o.optString("kind"))
        assertEquals(true, o.optBool("enter"))
        assertFailsWith<IllegalArgumentException> { Commands.paste(pc, "", group = "t", by = pc, now = now, signer = root) }
        assertFailsWith<IllegalArgumentException> { Commands.paste(pc, "x".repeat(Commands.MAX_TYPE_TEXT + 1), "type", group = "t", by = pc, now = now, signer = root) }
        assertFailsWith<IllegalArgumentException> { Commands.paste(pc, "x", "drop", group = "t", by = pc, now = now, signer = root) }
        // A paste of images or files names the copy by its event ID and is never typed.
        val copy = "00112233445566778899aabbccddeeff"
        val media = Wire.parse(Commands.paste(pc, copy, kind = "media", group = "t", by = pc, now = now, signer = root).body)!!
        assertEquals("media", media.optString("kind"))
        assertEquals("paste", media.optString("mode"))
        assertEquals(copy, media.optString("text"))
        assertFailsWith<IllegalArgumentException> { Commands.paste(pc, copy, "type", kind = "media", group = "t", by = pc, now = now, signer = root) }
        assertFailsWith<IllegalArgumentException> { Commands.paste(pc, "photo.png", kind = "media", group = "t", by = pc, now = now, signer = root) }
        assertFailsWith<IllegalArgumentException> { Commands.paste(pc, copy.uppercase(), kind = "media", group = "t", by = pc, now = now, signer = root) }
        assertFailsWith<IllegalArgumentException> { Commands.paste(pc, "x", kind = "file", group = "t", by = pc, now = now, signer = root) }
        val off = Wire.parse(Commands.pasteOff(pc, "t", pc, now, root).body)!!
        assertEquals("paste-off", off.optString("type"))
        assertNull(off.opt("text"))
    }

    /** The public key of testdata/interop/go-sealed-commands.json, whose secret Go opens the commands with. */
    private fun sealPublic(): ByteArray = Interop.read("go-sealed-commands.json").jsonObject.optBytes("public")!!

    /**
     * A command to a device whose record has a key for sealed messages carries
     * its orders sealed, through the core: the header stays, the text is gone,
     * and the core takes the body as a command.
     */
    @Test
    fun sealedCommand() {
        val c = Commands.paste(pc, "a secret <text>", kind = "secret", group = "tag", by = pc, now = now, signer = SoftwareSigner(), seal = sealPublic())
        val text = c.body.decodeToString()
        assertTrue("a secret" !in text, text)
        assertTrue("\"sealed\":" in text && "\"v\":2" in text, text)
        assertNull(Core.bodyRefusal("command", c.body))
        val o = Wire.parse(c.body)!!
        assertEquals("paste", o.optString("type"))
        assertEquals(pc, o.optString("to"))
        assertNull(o.opt("text"))
        assertFailsWith<Core.Refusal> { Commands.paste(pc, "x", group = "tag", by = pc, now = now, signer = SoftwareSigner(), seal = byteArrayOf(1, 2, 3)) }
    }

    /**
     * Writes commands this kit signed, with the root key and with an admin
     * CA's, and the records that name both, for internal/group's
     * TestSwiftCommand, under the Swift kit's file name, when
     * CBB_INTEROP_OUT names a directory.
     */
    @Test
    fun commandsForGo() {
        val dir = Interop.out ?: return
        val root = SoftwareSigner()
        val ca = GroupCertificates.groupCA(root, now, pathLength = 1)
        val tag = GroupCertificates.tag(ca)
        val admin = SoftwareSigner()
        val adminCA = GroupCertificates.adminCA("fedcba9876543210fedcba9876543210", admin.publicKeyDER, ca, root)
        // The records name the root's own device and the admin phone, which may sign every command.
        val by = "0123456789abcdef0123456789abcdef"
        val adminBy = "fedcba9876543210fedcba9876543210"
        val set = RecordSet()
        set.signed(V2.device(by, "Root", "phone", Records.keyHash(SoftwareSigner().publicKeyDER), root, now, holdsRoot = true), root, ca)
        set.signed(V2.device(adminBy, "Admin", "phone", Records.keyHash(SoftwareSigner().publicKeyDER), root, now, Records.keyHashOfCert(adminCA)), root, ca)
        val commands = listOf(
            Commands.mode(pc, "receive", tag, by, now, root),
            Commands.mode(pc, "receive", tag, adminBy, now, admin, adminCA),
            Commands.hub(
                pc,
                "203.0.113.9:8764" to "AAAA",
                emptyList(),
                listOf(PhoneHub.Client("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ByteArray(32) { 1 }, ByteArray(32) { 2 })),
                tag,
                by,
                now,
                root,
            ),
            Commands.paste(pc, "echo <ok> & \"done\"\n", "type", enter = true, group = tag, by = adminBy, now = now, signer = admin, adminCA = adminCA),
            Commands.pasteOff(pc, tag, by, now, root),
            Commands.action(pc, "lock", tag, adminBy, now, admin, adminCA),
            Commands.actionsOff(pc, tag, by, now, root),
            Commands.paste(pc, "sealed <text>", group = tag, by = adminBy, now = now, signer = admin, adminCA = adminCA, seal = sealPublic()),
            Commands.mute(pc, 3_600_000, tag, adminBy, now, admin, adminCA),
            Commands.unmute(pc, tag, by, now, root),
            Commands.paste(pc, "00112233445566778899aabbccddeeff", kind = "media", group = tag, by = adminBy, now = now, signer = admin, adminCA = adminCA),
        )
        // The eighth is sealed, for Go to open: a phone opens none.
        for ((i, c) in commands.withIndex()) if (i != 7) Commands.verify(c, set, pc, now.toEpochMilli())
        val out = Wire.obj(
            "group_ca" to Wire.bytes(ca),
            "records" to JsonArray(set.records.map { it.toJson() }),
            "to" to Wire.str(pc),
            "commands" to JsonArray(commands.map { it.toJson() }),
        )
        File(dir, "swift-command.json").writeBytes(Wire.encode(out))
    }

    /** testdata/interop/v2-commands.json, from Go's TestGoCommandVectors: which commands for this phone count. */
    @Test
    fun goCommands() {
        val v = Interop.read("v2-commands.json").jsonObject
        val set = RecordSet()
        val records = v.getValue("records").jsonArray.map { Member.Record.fromJson(it.jsonObject) }
        assertEquals(records.size, set.addAll(records, b64(v.str("group_ca"))).size)
        val now = v.getValue("now_ms").jsonPrimitive.long
        set.nowMS = now
        val commands = v.getValue("commands").jsonArray.map { it.jsonObject }
        assertEquals(17, commands.size)
        for (c in commands) {
            val name = c.str("name")
            val r = Member.Record.fromJson(c.getValue("command").jsonObject)
            val got = runCatching { Commands.verify(r, set, v.str("self"), now) }
            assertEquals(c.getValue("ok").jsonPrimitive.boolean, got.isSuccess, "$name: ${got.exceptionOrNull()?.message}")
            got.getOrNull()?.let { assertEquals(c["mode"]?.jsonPrimitive?.content, it.mode, name) }
            got.getOrNull()?.let {
                val (sender, verified) = set.commandSender(r, v.str("self"))
                assertEquals(c["verified"]?.jsonPrimitive?.boolean ?: false, verified, name)
                assertTrue(if (verified) sender == it.by else sender.startsWith("key "), "$name: $sender")
            }
            got.getOrNull()?.takeIf { it.type == "paste" }?.let { assertTrue(it.enter && it.kind == "text" && it.text!!.endsWith("\"done\"\n"), name) }
        }
    }

    /**
     * testdata/interop/go-sealed-commands.json, from Go: commands sealed to this member open with its secret, whose
     * public key the core gives, and are refused without it or when they do not open.
     */
    @Test
    fun goSealedCommands() {
        val v = Interop.read("go-sealed-commands.json").jsonObject
        val secret = b64(v.str("secret"))
        assertTrue(Core.sealPublic(secret).contentEquals(b64(v.str("public"))))
        assertFailsWith<Core.Refusal> { Core.sealPublic(byteArrayOf(1, 2, 3)) }
        val set = RecordSet()
        set.addAll(emptyList(), b64(v.str("group_ca")))
        val now = v.getValue("now_ms").jsonPrimitive.long
        var opened = 0
        for (c in v.getValue("commands").jsonArray.map { it.jsonObject }) {
            val name = c.str("name")
            val r = Member.Record.fromJson(c.getValue("command").jsonObject)
            val opens = c.getValue("ok").jsonPrimitive.boolean && c.getValue("opens").jsonPrimitive.boolean
            val got = runCatching { Commands.verify(r, set, v.str("self"), now, secret) }
            assertEquals(opens, got.isSuccess, "$name: ${got.exceptionOrNull()?.message}")
            got.getOrNull()?.let {
                assertEquals(c["mode"]?.jsonPrimitive?.content, it.mode, name)
                assertEquals(c["text"]?.jsonPrimitive?.content, it.text, name)
                assertFailsWith<Commands.Refused>(name) { Commands.verify(r, set, v.str("self"), now) }
                opened++
            }
        }
        assertEquals(2, opened)
    }

    /** testdata/interop/v2-actions.json, from Go's TestGoActionVectors: action commands for a member, as Go checks them. */
    @Test
    fun goActions() {
        val v = Interop.read("v2-actions.json").jsonObject
        val set = RecordSet()
        val records = v.getValue("records").jsonArray.map { Member.Record.fromJson(it.jsonObject) }
        assertEquals(records.size, set.addAll(records, b64(v.str("group_ca"))).size)
        val now = v.getValue("now_ms").jsonPrimitive.long
        val commands = v.getValue("commands").jsonArray.map { it.jsonObject }
        assertEquals(6, commands.size)
        for (c in commands) {
            val name = c.str("name")
            val got = runCatching { Commands.verify(Member.Record.fromJson(c.getValue("command").jsonObject), set, v.str("self"), now) }
            assertEquals(c.getValue("ok").jsonPrimitive.boolean, got.isSuccess, "$name: ${got.exceptionOrNull()?.message}")
            got.getOrNull()?.let { assertEquals(c["action"]?.jsonPrimitive?.content, it.action, name) }
        }
    }

    @Test
    fun actionCommands() {
        val rootKey = SoftwareSigner()
        val g = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, now)
        val o = Wire.parse(g.actionCommand(pc, "reboot", rootKey, now).body)!!
        assertEquals("action", o.optString("type"))
        assertEquals("reboot", o.optString("action"))
        assertEquals("actions-off", Wire.parse(g.actionsOffCommand(pc, rootKey, now).body)!!.optString("type"))
        assertFailsWith<IllegalArgumentException> { g.actionCommand(pc, "Reboot now", rootKey, now) }
        assertTrue(Commands.validActionName("cancel-shutdown"))
        for (bad in listOf("", "-x", "1x", "X", "a".repeat(33), "a b")) assertTrue(!Commands.validActionName(bad), bad)
    }

    /** The reason of a result is shown to a person: short, without control characters. */
    @Test
    fun cleanReason() {
        assertEquals("the screen is locked", Member.cleanReason("the screen is locked"))
        assertEquals("", Member.cleanReason(""))
        assertEquals("a [2Jb ]52;c;ZXZpbA== c", Member.cleanReason("a\u001b[2Jb\u001b]52;c;ZXZpbA==\u0007c"))
        assertEquals("a b c ", Member.cleanReason("a\nb\tc\r"))
        assertEquals("a b", Member.cleanReason("a\u009bb"))
        assertEquals("écran verrouillé", Member.cleanReason("écran verrouillé"))
        assertEquals(Member.MAX_REASON, Member.cleanReason("a".repeat(1000)).toByteArray().size)
        // A character that would cross the limit goes whole.
        assertEquals("a".repeat(Member.MAX_REASON - 1), Member.cleanReason("a".repeat(Member.MAX_REASON - 1) + "é"))
        assertTrue(Member.cleanReason("é".repeat(300)).toByteArray().size <= Member.MAX_REASON)
    }

    /**
     * A mute command carries its time, and none for until an unmute; a time past 30 days is refused. The hello
     * carries a mute and reads a time out of range as 30 days, as Go does.
     */
    @Test
    fun mute() {
        val root = SoftwareSigner()
        val tag = "0123456789abcdef"
        val by = "0123456789abcdef0123456789abcdef"
        for ((ms, want) in listOf(900_000L to 900_000L, 0L to 0L)) {
            assertEquals(want, Commands.parse(Commands.mute(pc, ms, tag, by, now, root).body).forMS)
        }
        assertFailsWith<IllegalArgumentException> { Commands.mute(pc, Commands.MAX_MUTE_MS + 1, tag, by, now, root) }
        assertEquals("unmute", Commands.parse(Commands.unmute(pc, tag, by, now, root).body).type)

        val hello = Member.Hello(wallMS = 1, muted = true, mutedForMS = 60_000)
        val back = Member.decode(Member.encode(Member.Message.Hello(Member.Role.PHONE, hello)).let { it.copyOfRange(4, it.size) })
        assertEquals(Member.Message.Hello(Member.Role.PHONE, hello), back)
        val none = String(Member.encode(Member.Message.Hello(Member.Role.PHONE, Member.Hello(wallMS = 1))).let { it.copyOfRange(4, it.size) })
        assertTrue("muted" !in none)
        val long = Member.decode("""{"t":"hello","role":"member","hello":{"wall_ms":1,"muted":true,"muted_for_ms":99999999999}}""".toByteArray())
        val got = (long as Member.Message.Hello).hello
        assertTrue(got.muted)
        assertEquals(Commands.MAX_MUTE_MS, got.mutedForMS)
    }
}
