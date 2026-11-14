// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.Manifest
import android.app.Notification
import android.app.NotificationManager
import android.appwidget.AppWidgetManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.net.ConnectivityManager
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.isRoot
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.printToString
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters

/**
 * The phone makes its own group and admits a computer of the bench's fleet
 * by its QR code's text, then syncs with it both ways
 * (docs/maintainers/testbench-catalogue.md, A1 on Android). The steps share the app's
 * state in order: the group the first step makes is the next ones' group,
 * and Gradle uninstalls the app after the run.
 */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class GroupTest {
    // The app's own activity: it shows the screens, keeps the group in the
    // foreground and is the screen the prompts before signing need.
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @get:Rule val permissions: GrantPermissionRule =
        if (Build.VERSION.SDK_INT >= 33) GrantPermissionRule.grant(Manifest.permission.CAMERA, Manifest.permission.POST_NOTIFICATIONS)
        else GrantPermissionRule.grant(Manifest.permission.CAMERA)

    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext

    /** The phone's networks for a failure message: which is the default, each one's capabilities and addresses. */
    @Suppress("DEPRECATION")
    private fun networks(): String {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return "no ConnectivityManager"
        val active = cm.activeNetwork
        return cm.allNetworks.joinToString("; ", prefix = "default ${active ?: "none"}: ") { n ->
            "$n ${cm.getNetworkCapabilities(n)} ${cm.getLinkProperties(n)?.linkAddresses}"
        }
    }
    private lateinit var model: AppModel

    private fun str(id: Int) = context.getString(id)

    @Before
    fun show() {
        assumeTrue("the bench's phone suite passes the helper's address", Bench.address != null)
        // The app's own model, which MainActivity, the tile, the widget and Share use.
        model = (context.applicationContext as CBBApp).model
        compose.waitForIdle()
        // Android hands the clipboard only to the app whose window has the
        // focus and gives the others nothing: until MainActivity's window
        // takes it from the test's own empty activity, the button reads no
        // clipboard and says "nothing new", which a person, who presses it
        // in the window, never sees.
        compose.waitUntil(10_000) { compose.runOnUiThread { compose.activity.hasWindowFocus() } }
    }

    /** Waits on the test's thread until ok holds, up to seconds. */
    private fun until(seconds: Int, what: String, ok: () -> Boolean) {
        val deadline = System.currentTimeMillis() + seconds * 1000L
        while (!ok()) {
            if (System.currentTimeMillis() > deadline) throw AssertionError("not within ${seconds}s: $what")
            Thread.sleep(250)
        }
    }

    private fun clipboard(): ClipboardManager = context.getSystemService(ClipboardManager::class.java)

    private fun setClip(text: String) = InstrumentationRegistry.getInstrumentation().runOnMainSync {
        clipboard().setPrimaryClip(ClipData.newPlainText("test", text))
    }

    private fun clip(): String? {
        var text: String? = null
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            text = clipboard().primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()
        }
        return text
    }

    /** A1: Start, "Create a group", the QR code's text, Add: the phone's own group with the computer in it. */
    @Test
    fun a1_admitComputer() {
        assertEquals(AppModel.Phase.START, model.phase)
        compose.onNodeWithText(str(R.string.create_group)).performClick()
        val (code, pairing) = Bench.pairCode(Bench.PC)
        typeAndAdd(code)
        until(90, "the phone admits ${Bench.PC}; the app says ${model.message}") { model.phase == AppModel.Phase.HOME }
        val out = pairing.finish(60)
        assertTrue("cbb pair on ${Bench.PC} did not join:\n$out", out.contains("Joined the group"))
        until(30, "${Bench.PC} in the phone's devices: ${model.group.devices.map { it.name }}") {
            model.group.devices.any { it.name == Bench.PC }
        }
        val status = Bench.run(Bench.PC, "cbb status")
        assertFalse("cbb status on ${Bench.PC} shows no group:\n$status", status.contains("Not in a group"))
    }

    /**
     * Waits until the phone is connected to name and no sync is going: a
     * step that presses the button once, or sends once, starts as a person
     * does who sees the computer online. Right after joining the phone's
     * node starts again (the phone's hub), and the sync the app runs as its
     * window takes the focus may still wait for a computer; a copy set
     * meanwhile would go out with that sync, and the step's own press would
     * then find nothing new.
     */
    private fun settled(name: String) {
        until(60, "the phone connected to $name and idle: busy ${model.busy}, devices ${model.group.devices.map { "${it.name} online ${it.online}" }}") {
            var idle = false
            InstrumentationRegistry.getInstrumentation().runOnMainSync { idle = !model.busy }
            idle && model.group.devices.any { it.name == name && it.online }
        }
    }

    /** A1: the big button sends the phone's copy to the computer. */
    @Test
    fun a2_sendToComputer() {
        settled(Bench.PC)
        val text = "cbb-bench phone A1 from the phone ${System.currentTimeMillis()}"
        setClip(text)
        runBlocking { model.sync() }
        assertEquals("the button says ${model.message}", R.string.sent, model.message?.text)
        Bench.arrives(Bench.PC, text)
    }

    /** A1: the big button fetches the computer's copy onto the phone's clipboard. */
    @Test
    fun a3_fetchFromComputer() {
        val text = "cbb-bench phone A1 from ${Bench.PC} ${System.currentTimeMillis()}"
        Bench.copy(Bench.PC, text)
        until(30, "the phone fetches ${Bench.PC}'s copy; the button says ${model.message}") {
            runBlocking { model.sync() }
            clip() == text
        }
    }

    /** The computer's device ID in the phone's list. */
    private fun idOf(name: String): String = model.group.devices.firstOrNull { it.name == name }?.id
        ?: throw AssertionError("no $name in the phone's devices: ${model.group.devices.map { it.name }}")

    /** M7: a new phone syncs (shared): a computer's new copy comes onto it without the button. */
    @Test
    fun a4_receivesByItself() {
        assertEquals("a new phone's mode", "shared", model.group.syncMode)
        val text = "cbb-bench phone M7 by itself ${System.currentTimeMillis()}"
        Bench.copy(Bench.PC, text)
        until(30, "${Bench.PC}'s copy on the phone's clipboard without the button; it has ${clip()}") { clip() == text }
    }

    /** M7: in the mode send the phone leaves its clipboard alone; shared again, it takes copies. */
    @Test
    fun a5_sendModeKeepsClipboard() {
        model.group.setOwnMode("send")
        assertEquals("send", model.group.syncMode)
        try {
            val before = clip()
            val text = "cbb-bench phone M7 not taken ${System.currentTimeMillis()}"
            Bench.copy(Bench.PC, text)
            Thread.sleep(10_000)
            assertEquals("in the mode send the phone took ${Bench.PC}'s copy", before, clip())
        } finally {
            model.group.setOwnMode("shared")
        }
        assertEquals("shared", model.group.syncMode)
    }

    /** T16: "Paste on it…" types and pastes into the computer's tmux, with Enter and as a secret. */
    @Test
    fun a6_pasteOnComputer() {
        val pc = idOf(Bench.PC)
        // The line of cbb.conf that starts the helper, and a client attached on a terminal.
        Bench.run(Bench.PC, "tmux new-session -d -s cbb -x 120 -y 30 && tmux run-shell -b 'cbb paste-helper tmux >/tmp/cbb-helper.log 2>&1 || true'")
        Bench.run(Bench.PC, "cbb paste-receive on -console -enter")
        Bench.start(Bench.PC, "TERM=xterm sh -c 'sleep infinity | script -qfc \"tmux attach -t cbb\" /dev/null'")
        until(10, "a tmux client on ${Bench.PC}") { Bench.run(Bench.PC, "tmux list-clients").isNotBlank() }
        val pane = { Bench.run(Bench.PC, "tmux capture-pane -p -J -t cbb") }
        settled(Bench.PC)
        for ((method, secret) in listOf("type" to false, "paste" to false, "paste" to true)) {
            val text = "cbbbench$method${if (secret) "secret" else ""}${System.currentTimeMillis()}"
            // The receiver takes one paste a second from a sender.
            Thread.sleep(1_100)
            val done = runBlocking { model.paste(pc, text, method, enter = true, secret = secret) }
            assertTrue("$method${if (secret) " as a secret" else ""} refused: ${model.message}", done)
            until(20, "the pane on ${Bench.PC} shows $text:\n${pane()}") { pane().contains(text) }
        }
    }

    /** Q8: a quick action the computer allows runs from the phone; turned all off, the next is refused. */
    @Test
    fun a7_quickActions() {
        val pc = idOf(Bench.PC)
        Bench.run(Bench.PC, "cbb action enable restart -any-key -yes")
        val pid = { Bench.run(Bench.PC, "pgrep -o -f '^cbb service'").trim() }
        val before = pid()
        assertTrue("restart refused: ${model.message}", runBlocking { model.runAction(pc, "restart") })
        until(30, "the service on ${Bench.PC} restarted") { runCatching { pid() }.getOrDefault(before).let { it.isNotEmpty() && it != before } }
        until(60, "the phone connected to ${Bench.PC} again") { model.group.devices.any { it.name == Bench.PC && it.online } }
        assertTrue("turning all off refused: ${model.message}", runBlocking { model.actionsOff(pc) })
        assertFalse("restart ran after all were turned off", runBlocking { model.runAction(pc, "restart") })
    }

    /** A1: a second computer admitted, renamed and removed; the removed one says so. */
    @Test
    fun a8_renameAndRemove() {
        val second = Bench.add()
        admit(second)
        // A6: one notification that it joined.
        val joined = context.getString(R.string.event_added, second)
        until(30, "a notification \"$joined\"; there are ${notifications()}") {
            runBlocking { model.refresh() }
            notifications().contains(joined)
        }
        assertEquals("notifications of the join: ${notifications()}", 1, notifications().count { it == joined })
        val id = idOf(second)
        runBlocking { model.rename(id, "bench-second") }
        assertEquals("renaming says ${model.message}", R.string.renamed, model.message?.text)
        until(30, "the new name on ${Bench.PC}") { Bench.run(Bench.PC, "cbb status").contains("bench-second") }
        // Only a connected device gets the record that removes it (docs/protocol.md, section 10,
        // revocation): afterwards every member refuses it. The phone's first dial to a
        // computer that just joined can fail, so the removal waits for the connection.
        until(60, "the phone connected to $second") {
            runBlocking { model.refresh() }
            model.group.devices.any { it.id == id && it.online }
        }
        until(30, "the new name on $second") { Bench.run(second, "cbb status").contains("bench-second") }
        // A6: with the switch for devices off, the removal notifies of nothing.
        model.notifier.set(GroupEvent.Kind.DEVICES, false)
        try {
            runBlocking { model.remove(id) }
            assertEquals("removing says ${model.message}", R.string.removed, model.message?.text)
            until(60, "$second says it was removed") { Bench.run(second, "cbb status").contains("removed from the group") }
            runBlocking { model.refresh() }
            Thread.sleep(2_000)
            val removed = context.getString(R.string.event_removed, "bench-second")
            assertFalse("a notification with its switch off: ${notifications()}", notifications().contains(removed))
        } finally {
            model.notifier.set(GroupEvent.Kind.DEVICES, true)
        }
        // A6: never the clipboard's text.
        assertFalse("a notification shows a copy: ${notifications()}", notifications().any { it.contains("cbb-bench phone") })
    }

    /**
     * Types the QR code's text on the add page and taps Add once the button
     * takes it, scrolled into view: below a working camera's preview the
     * page scrolls, and a tap outside the screen reaches nothing.
     */
    private fun typeAndAdd(code: String) {
        compose.onNode(hasSetTextAction()).performScrollTo().performTextInput(code)
        val add = compose.onNodeWithText(str(R.string.add))
        until(10, "Add takes the code") { runCatching { add.assertIsEnabled() }.isSuccess }
        // The keyboard that the text brought up shrinks the page as it
        // slides in, and a tap below the page's new bottom reaches nothing:
        // scroll to Add once the page settled, and again if a tap was lost
        // (a second tap while the app admits does nothing).
        // Pairing takes seconds: the app is busy, or it says why it is not.
        val started = { model.busy || model.message != null }
        for (i in 1..3) {
            // Admitted already, the page closed.
            if (i > 1 && runCatching { add.assertExists() }.isFailure) return
            compose.waitForIdle()
            add.performScrollTo()
            compose.waitForIdle()
            add.performClick()
            if (runCatching { until(5, "the app starts admitting") { started() } }.isSuccess) return
        }
        throw AssertionError("not within 15s: the app starts admitting\n${appState()}")
    }

    /** Admits a member in no group from Home's + menu, by its QR code's text. */
    private fun admit(dev: String) {
        compose.onNodeWithContentDescription(str(R.string.add_device)).performClick()
        compose.onNodeWithText(str(R.string.scan_code)).performClick()
        val (code, pairing) = Bench.pairCode(dev)
        typeAndAdd(code)
        val out = try {
            pairing.finish(90)
        } catch (e: AssertionError) {
            throw AssertionError("${e.message}\n${appState()}\n$dev's log:\n${Bench.logs(dev)}")
        }
        assertTrue("cbb pair on $dev did not join:\n$out", out.contains("Joined the group"))
        until(30, "$dev in the phone's devices") { model.group.devices.any { it.name == dev } }
    }

    /**
     * What the app shows and where its threads wait, for a failure's
     * message: the phase, whether it is busy, its message, and the stacks of
     * the threads that run the app's code.
     */
    private fun appState(): String {
        val note = model.message?.let { "${str(it.text)} ${it.detail.orEmpty()}" }
        val stacks = Thread.getAllStackTraces().filter { (_, s) -> s.any { it.className.startsWith("tools.cbb") } }
            .entries.joinToString("\n") { (t, s) -> "${t.name} (${t.state}):\n" + s.take(25).joinToString("\n") { "  at $it" } }
        val screen = runCatching { compose.onAllNodes(isRoot()).printToString(maxDepth = 30) }.getOrElse { it.toString() }
        return "the app: phase ${model.phase}, busy ${model.busy}, message $note\nthe screen:\n$screen\n$stacks"
    }

    /** The texts of the app's notifications that show now. */
    private fun notifications(): List<String> = context.getSystemService(NotificationManager::class.java).activeNotifications
        .mapNotNull { it.notification.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() }

    /** A12: the widget's and the tile's tap opens the send screen, which sends the copy without the app. */
    @Test
    fun a9_sendFromTileAndWidget() {
        val widgets = AppWidgetManager.getInstance(context).getInstalledProvidersForPackage(context.packageName, null)
        assertTrue("no home-screen widget: $widgets", widgets.any { it.provider.className == SendWidget::class.java.name })
        val text = "cbb-bench phone A12 from the tile ${System.currentTimeMillis()}"
        // In the mode own only the button sends: shared would send the new copy by itself.
        model.group.setOwnMode("own")
        try {
            // Settles what earlier tests left, so the send screen finds the group connected.
            runBlocking { model.sync() }
            // A computer's copy of a moment ago, from an earlier test, is what the button
            // fetches first instead of sending.
            until((model.group.incomingMS / 1000).toInt() + 15, "no copy of a moment ago from another device: ${model.group.recentCopy}") {
                model.group.recentCopy == null
            }
            setClip(text)
            InstrumentationRegistry.getInstrumentation().runOnMainSync { model.message = null }
            // What the widget's and the tile's PendingIntent start.
            assertEquals("the phone's clipboard before the send screen", text, clip())
            context.startActivity(SendActivity.intent(context))
            try {
                Bench.arrives(Bench.PC, text)
            } catch (e: Throwable) {
                throw AssertionError("${e.message}; the send screen says ${model.message}; the latest copy ${model.group.recentCopy}; the phone's clipboard has ${clip()}", e)
            }
            until(10, "the send screen says it sent; it says ${model.message}") { model.message?.text == R.string.sent }
        } finally {
            model.group.setOwnMode("shared")
        }
    }

    /** O11: Share sends a file, which the computer saves; a file the computer copies lands in Downloads. */
    @Test
    fun b1_files() {
        val stamp = System.currentTimeMillis()
        // Shared as another app shares a file: through a provider's content
        // URI (here Downloads'), never a file:// path the app would read itself.
        val sent = context.contentResolver.insert(
            MediaStore.Downloads.EXTERNAL_CONTENT_URI,
            ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, "o11-$stamp.txt")
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
            },
        ) ?: throw AssertionError("cannot add o11-$stamp.txt to Downloads")
        context.contentResolver.openOutputStream(sent)!!.use { it.write("cbb-bench phone O11 from the phone $stamp\n".toByteArray()) }
        // The phone's node as the test began: one made while it runs starts without the copies before it.
        val nodeAtStart = model.group.nodeNumber
        val note = try {
            runBlocking { model.sendShared(listOf(sent)) }
        } finally {
            context.contentResolver.delete(sent, null, null)
        }
        assertEquals("Share says ${model.message}; ${phoneSide(nodeAtStart)}", R.string.files_sent, note.text)
        var saved = ""
        try {
            until(60, "${Bench.PC} saves the phone's file") {
                saved = runCatching { Bench.run(Bench.PC, "rm -rf /tmp/o11 && mkdir /tmp/o11 && cbb paste -o /tmp/o11 2>&1; find /tmp/o11 -type f -exec cat {} +") }
                    .getOrElse { it.toString() }
                saved.contains("from the phone $stamp")
            }
        } catch (e: AssertionError) {
            throw AssertionError("${e.message}; cbb paste -o and the files give:\n$saved\n${phoneSide(nodeAtStart)}\n${pcSide()}")
        }
        val back = "o11-back-$stamp.txt"
        val copied = Bench.run(Bench.PC, "mkdir -p /tmp/o11src && printf 'cbb-bench phone O11 from the computer $stamp' >/tmp/o11src/$back && cbb copy /tmp/o11src/$back 2>&1")
        try {
            // The button waits until the computer's copy is here: pressed
            // before it, it sends what the phone's clipboard holds (a9's
            // text, which the phone's own files replaced), and that newer
            // copy wins over the computer's (SyncRule.decide).
            until(30, "${Bench.PC}'s files reach the phone") { model.group.recentCopy?.media?.isFiles == true }
            until(60, "the phone saves ${Bench.PC}'s file") {
                runBlocking { model.sync() }
                model.message?.text == R.string.files_saved
            }
        } catch (e: AssertionError) {
            // Read now, after the last sync, not when the wait began.
            throw AssertionError(
                "${e.message}; the button says ${model.message?.let { context.getString(it.text) + (it.detail?.let { d -> ": $d" } ?: "") }}; " +
                    "${model.group.copyState}; cbb copy said: $copied\n${phoneSide(nodeAtStart)}\n${pcSide()}",
            )
        }
        val cr = context.contentResolver
        val uri = cr.query(
            MediaStore.Downloads.EXTERNAL_CONTENT_URI, arrayOf(MediaStore.Downloads._ID),
            "${MediaStore.Downloads.DISPLAY_NAME} = ?", arrayOf(back), null,
        )?.use { c -> if (c.moveToFirst()) Uri.withAppendedPath(MediaStore.Downloads.EXTERNAL_CONTENT_URI, c.getLong(0).toString()) else null }
            ?: throw AssertionError("no $back in Downloads")
        val got = cr.openInputStream(uri)!!.use { it.readBytes().toString(Charsets.UTF_8) }
        assertEquals("cbb-bench phone O11 from the computer $stamp", got)
    }

    /**
     * The phone's side of a copy that went missing, for a failure's message:
     * whether its node was made again since the test began, the node's
     * connections and what it sent, took and dropped lately (and the
     * stopped nodes' the same), and its sync mode.
     */
    private fun phoneSide(nodeAtStart: Int): String {
        val now = model.group.nodeNumber
        val made = if (now == nodeAtStart) "the phone's node is the one from the test's start (#$now)" else "the phone's node was made again: #$nodeAtStart at the start, #$now now"
        val self = model.group.devices.firstOrNull { it.isSelf }
        return "$made; the phone is ${self?.id} in mode ${self?.mode}, online ${model.group.online}\nthe phone's nodes:\n${model.group.nodeDiagnostics}"
    }

    /** The computer's side: its status, with the members it is connected to, and its log. */
    private fun pcSide(): String =
        "${Bench.PC}'s status:\n${runCatching { Bench.run(Bench.PC, "cbb status 2>&1") }.getOrElse { it.toString() }}\n${Bench.PC}'s log:\n${Bench.logs(Bench.PC)}"

    /** Y35: a computer's secret comes onto the phone marked sensitive; cbb paste -terminal refuses it without -secret. */
    @Test
    fun b2_secrets() {
        val text = "cbbbenchY35secret${System.currentTimeMillis()}"
        Bench.run(Bench.PC, "cbb copy -secret", stdin = text)
        val refused = Bench.run(Bench.PC, "cbb paste -terminal 2>&1; echo exit=$?")
        assertTrue("cbb paste -terminal gave a secret without -secret:\n$refused", refused.contains("add -secret") && !refused.contains("exit=0"))
        assertEquals(text, Bench.run(Bench.PC, "cbb paste -terminal -secret").trim())
        until(30, "the secret on the phone's clipboard; it has ${clip()}") {
            runBlocking { model.sync() }
            clip() == text
        }
        var sensitive = false
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            sensitive = clipboard().primaryClip?.description?.extras?.getBoolean("android.content.extra.IS_SENSITIVE") == true
        }
        assertTrue("the secret is not marked sensitive on the phone", sensitive)
    }

    /**
     * W16 and G14: the phone is the group's hub while its app is open, at a
     * forwarder: a wrong key is refused with the reason, the right one
     * registers, a computer away reaches the phone through it, an
     * invitation the phone serves admits a computer, and the network the
     * phone is on becomes a home network.
     */
    @Test
    fun c1_phoneHub() {
        val hubNow = { runBlocking { model.refresh() }; model.hub ?: throw AssertionError("the phone cannot be the hub") }
        val (fwd, key) = Bench.forwarder()
        runBlocking { model.setHub(true) }
        try {
            // Turned on, the hub takes the project's forwarder, or none, for
            // home only, when the emulator cannot look its name up.
            hubNow().let {
                if (it.forwarder == null) {
                    assertEquals("the hub without a forwarder: ${model.hubNote}", HubOnPhone.Status.HOME_ONLY, it.status)
                } else {
                    assertTrue("the hub's first forwarder is not the project's: ${it.forwarder}", it.forwarder?.isProject == true)
                }
            }
            runBlocking { model.setForwarder(fwd, java.util.Base64.getEncoder().encodeToString(ByteArray(32))) }
            until(60, "a wrong key refused with the reason; the app says ${model.hub}") {
                hubNow().let { it.status == HubOnPhone.Status.FAILED && it.error != null }
            }
            runBlocking { model.setForwarder(fwd, key) }
            assertEquals("setting the forwarder says ${model.hubNote}", null, model.hubNote)
            until(60, "the phone registered at $fwd; the app says ${model.hub}") { hubNow().status == HubOnPhone.Status.REGISTERED }

            // At home the computer learns the phone hub's offer over its connection to the phone.
            Bench.run(Bench.PC, "cbb global on", stdin = "yes\n")
            var global = ""
            try {
                until(120, "${Bench.PC} learns the phone hub's offer") {
                    // The computer connects again for its hello to carry its tunnel key; the phone dials it.
                    runBlocking { model.sync() }
                    global = runCatching { Bench.run(Bench.PC, "cbb global") }.getOrElse { it.toString() }
                    global.contains("the hub is")
                }
                // Away: the phone no longer reaches the computer's member port, whose connection ends,
                // so the computer reaches the phone through the forwarder.
                Bench.run(Bench.PC, CUT_HOME)
                until(180, "${Bench.PC} connected to the phone hub") {
                    // What the phone sends on its old connection meets the reset.
                    runBlocking { model.sync() }
                    global = runCatching { Bench.run(Bench.PC, "cbb global") }.getOrElse { it.toString() }
                    global.contains("connected to the hub")
                }
            } catch (e: AssertionError) {
                throw AssertionError("${e.message}:\n$global\nthe app says ${model.hub}\n${Bench.PC}'s log:\n${Bench.logs(Bench.PC)}")
            }

            // G14: an invitation the phone makes and serves, used by a new computer.
            runBlocking { model.openInvite() }
            val invite = model.invite ?: throw AssertionError("no invitation: ${model.inviteNote}")
            val guest = Bench.add()
            Bench.run(guest, "umask 077 && cat >/tmp/invite", stdin = invite.file.readText())
            val join = Bench.start(guest, "echo yes | cbb pair -invite /tmp/invite")
            try {
                until(120, "the phone asks about $guest") { model.invite?.request != null }
            } catch (e: AssertionError) {
                throw AssertionError("${e.message}; the job says ${join.output().first}\n$guest's log:\n${Bench.logs(guest)}")
            }
            InstrumentationRegistry.getInstrumentation().runOnMainSync { model.answer(true) }
            val out = join.finish(120)
            assertTrue("cbb pair -invite on $guest did not join:\n$out", out.contains("Joined the group"))
            until(30, "the invitation says it admitted $guest: ${model.inviteNote}") { model.inviteNote?.text == R.string.invite_admitted }
            until(60, "$guest in the phone's devices") { model.group.devices.any { it.name == guest } }

            // "This is my home network".
            runBlocking { model.addHomeNetwork() }
            assertEquals("adding the home network says (${networks()})", null, model.hubNote)
            assertTrue("the hub does not count this network as home: ${model.hub}", hubNow().home)
        } finally {
            runCatching { Bench.run(Bench.PC, CUT_HOME.replace(" -A ", " -D ")) }
            runCatching { Bench.run(Bench.PC, "cbb global off", stdin = "yes\n") }
            runBlocking { model.setHub(false) }
        }
        assertEquals("the hub turned off", HubOnPhone.Status.OFF, hubNow().status)
    }

    /**
     * W42 and W5: a computer the phone made an admin is the hub; it admits a
     * computer by itself, which the phone lists (G36); with sync away from
     * home on, the phone, which finds no hub on its network (the emulator
     * sees no mDNS), reaches it through the tunnel in the app's process,
     * marks it as the hub in use and shows the computer behind it online; the app and cbb global say where it stands, also while the hub
     * does not answer.
     */
    @Test
    fun c2_awayThroughHub() {
        val (hub, udp) = Bench.addHub()
        admit(hub)
        // The button shows once the computer's hello offered its admin key.
        until(60, "$hub offers its admin key") { model.group.devices.any { it.name == hub && it.canMakeAdmin } }
        runBlocking { model.makeAdmin(idOf(hub)) }
        assertEquals("making it an admin says ${model.message}", R.string.made_admin, model.message?.text)
        Bench.run(hub, "cbb global on", stdin = "yes\n")
        // The hub learns that it is an admin over its connection to the phone.
        until(60, "$hub takes cbb global hub") {
            runCatching { Bench.run(hub, "cbb global hub -port $udp -firewall no ${Bench.HOST}:$udp") }.isSuccess
        }
        val global = Bench.run(hub, "cbb global")
        assertTrue("cbb global on $hub:\n$global", global.contains("this device is the hub, on UDP port $udp") && global.contains("${Bench.HOST}:$udp"))
        // G36: the computer the phone made an admin admits a computer by
        // itself, and the phone, the root, takes its record and lists it.
        val guest = Bench.add()
        val window = Bench.start(hub, "cbb pair </dev/null")
        val code = window.line("Pairing code:").replace(" ", "")
        val at = window.line("If it cannot find this one: cbb pair -code")
        val joined = Bench.run(guest, "cbb pair -code $at", stdin = "$code\n", seconds = 90)
        assertTrue("cbb pair -code on $guest did not join:\n$joined", joined.contains("Joined the group"))
        val admitted = window.finish(60)
        assertTrue("cbb pair on $hub did not admit $guest:\n$admitted", admitted.contains("joined the group."))
        until(60, "$guest, admitted by $hub, in the phone's devices: ${model.group.devices.map { it.name }}") {
            runBlocking { model.sync() }
            model.group.devices.any { it.name == guest }
        }
        assertEquals("off before it is turned on", AwayFromHome.Status.OFF, model.away?.status ?: AwayFromHome.Status.OFF)
        runBlocking { model.setAway(true) }
        assertEquals("turning it on says ${model.awayNote}", null, model.awayNote)
        val status = { runBlocking { model.refresh() }; model.away }
        until(120, "the phone connected through $hub's tunnel; the app says ${model.away}") { status()?.status == AwayFromHome.Status.CONNECTED }
        // The phone's devices list marks the computer as the hub it reaches.
        until(60, "$hub marked as the hub in use: ${model.group.devices.firstOrNull { it.name == hub }}") {
            runBlocking { model.sync() }
            model.group.devices.any { it.name == hub && it.hub == LiveGroup.HubMark.IN_USE }
        }
        // The computer behind the hub shows online on the phone too.
        until(120, "$guest online on the phone: ${model.group.devices.firstOrNull { it.name == guest }}") {
            runBlocking { model.sync() }
            model.group.devices.any { it.name == guest && it.online }
        }
        val text = "cbb-bench phone W42 through the tunnel ${System.currentTimeMillis()}"
        Bench.copy(hub, text)
        until(30, "$hub's copy on the phone; it has ${clip()}") {
            runBlocking { model.sync() }
            clip() == text
        }
        // W5: the hub stops answering; the app says it is trying, and why.
        Bench.run(hub, "pkill -STOP -f '^cbb service'")
        try {
            until(180, "the app says it cannot reach $hub; it says ${model.away}") {
                status().let { it?.status == AwayFromHome.Status.CONNECTING && it.error != null }
            }
        } finally {
            Bench.run(hub, "pkill -CONT -f '^cbb service'")
        }
        until(120, "the phone through the tunnel again; the app says ${model.away}") { status()?.status == AwayFromHome.Status.CONNECTED }
        runBlocking { model.setAway(false) }
        assertEquals("off again", AwayFromHome.Status.OFF, status()?.status ?: AwayFromHome.Status.OFF)
    }

    private companion object {
        /**
         * Cuts the phone off from a member's port: both ends of a connection
         * there are reset, so neither keeps a stale one. With -D in place of
         * -A it undoes it.
         */
        const val CUT_HOME = "iptables -A INPUT -p tcp --dport 8764 -j REJECT --reject-with tcp-reset && " +
            "iptables -A OUTPUT -p tcp --sport 8764 -j REJECT --reject-with tcp-reset"
    }
}
