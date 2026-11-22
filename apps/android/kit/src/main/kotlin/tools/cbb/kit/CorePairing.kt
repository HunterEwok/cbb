// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Pairing in the Rust core (docs/core-api.md, "Joining and admitting"):
 * a phone that makes a group ([newGroup]), opens a pairing
 * window for a device at home ([Window]), joins a group by a window's QR
 * code ([Joiner]), or makes a remote invitation ([Inviting]). The core runs
 * the exchange inside its own TLS and asks for each signature through a
 * callback, so the keys stay in the Keystore.
 */
object CorePairing {
    /** Why a pairing failed: the core's message and details, and whether the code was wrong. */
    class Failure(message: String, val details: String? = null, val wrongCode: Boolean = false) : Exception(message) {
        override fun toString(): String = "CorePairing.Failure: $message" + (details?.takeIf { it.isNotEmpty() }?.let { "\n$it" } ?: "")
    }

    /** A group this phone made: its ID, this phone's device ID and the recovery sheet, which the person keeps and the app keeps nowhere. */
    class Made(val group: String, val device: String, val recoveryQR: String, val recoveryText: List<String>)

    /**
     * Makes a group with this phone's root key (cbb_group_new): the core writes this phone's record under the root and keeps
     * the set in dir, where [CoreMember.start] then reads it. rootPublic and
     * public are the root and member keys (SubjectPublicKeyInfo or point),
     * store where the member key lives (Records.HARDWARE or Records.FILE);
     * signRoot signs a digest with the root key, during this call only.
     */
    fun newGroup(dir: java.io.File, name: String, os: String, store: String, rootPublic: ByteArray, public: ByteArray, signRoot: (ByteArray) -> ByteArray): Made {
        val request = Wire.encode(
            Wire.obj(
                "dir" to Wire.str(dir.path),
                "name" to Wire.str(name),
                "os" to Wire.str(os),
                "store" to Wire.str(store),
                "root_public" to Wire.bytes(CoreMember.point(rootPublic)),
                "public" to Wire.bytes(CoreMember.point(public)),
            ),
        )
        val sign = CoreMember.signFn(signRoot)
        val count = count()
        val answer = lib.cbb_group_new(request, Core.SizeT(request.size.toLong()), sign, null, count)
            ?: throw Core.Mismatch("the core gave no answer to the new group")
        val o = ok("new group", CoreMember.take(answer, count))
        val r = o.optObject("recovery") ?: throw Core.Mismatch("the new group has no recovery sheet")
        return Made(
            o.optString("group") ?: throw Core.Mismatch("the new group has no ID"),
            o.optString("device") ?: throw Core.Mismatch("the new group has no device"),
            r.optString("qr") ?: "",
            r.optArray("text")?.map { (it as? JsonPrimitive)?.content ?: "" }.orEmpty(),
        )
    }

    /**
     * A remote invitation an admin phone makes (docs/protocol.md, section
     * 12) through member: its guest tunnel opens on this phone when it is
     * the group's hub, else through a connected hub of the group (hub
     * names one, "" for any). public is the key sign holds (the admin
     * key, or the root's key); sign is called when a device the user confirmed is
     * admitted. expiresS is in seconds: an hour when 0, a day at most. It
     * waits for the hub, so the app makes it off its main thread.
     */
    class Inviting(member: CoreMember, public: ByteArray, expiresS: Int, hub: String = "", kind: String = "", sign: (ByteArray) -> ByteArray) : Closeable {
        private val signFn = CoreMember.signFn(sign)
        private val handle: Pointer
        private val closed = AtomicBoolean(false)
        private val lock = Object()
        private var calls = 0

        /** A device that proved the invitation's secret: the app asks the user whether its fingerprint matches what the device shows. */
        data class Request(val device: String, val name: String, val os: String, val fingerprint: String)

        /** Where the invitation is: open, joining (answer about request), done (name joined) or failed. */
        data class State(val version: Long, val state: String, val request: Request?, val name: String, val failure: Failure?)

        /** The invitation's text, cbb://join#..., for its QR code, and how long it is valid, in seconds. */
        val text: String
        val expires: Int

        init {
            val request = Wire.encode(
                Wire.obj(
                    "public" to Wire.bytes(CoreMember.point(public)),
                    "expires" to JsonPrimitive(expiresS),
                    "hub" to Wire.str(hub),
                    "kind" to Wire.str(kind),
                ),
            )
            val answer = PointerByReference()
            val count = count()
            val h = lib.cbb_invite_new(member.handle, request, Core.SizeT(request.size.toLong()), signFn, null, answer, count)
            val got = answer.value?.let { CoreMember.take(it, count) } ?: throw Core.Mismatch("the core gave no answer to the invitation")
            val o = try {
                ok("invite", got)
            } catch (e: Exception) {
                h?.let { lib.cbb_invite_free(it) }
                throw e
            }
            handle = h ?: throw Core.Mismatch("the core made no invitation")
            text = o.optString("invite") ?: ""
            expires = (o.optLong("expires") ?: 0).toInt()
        }

        /** Waits up to timeoutMS for a state past version; it blocks, so the app calls it off its main thread. */
        fun next(version: Long, timeoutMS: Long = 1000): State {
            enter()
            try {
                val o = ok("invite", call { c -> lib.cbb_invite_next(handle, version, timeoutMS, c) })
                val r = o.optObject("joining")?.let {
                    Request(it.optString("device") ?: "", it.optString("name") ?: "", it.optString("os") ?: "", it.optString("fingerprint") ?: "")
                }
                val f = o.optObject("error")?.let { Failure(it.optString("message") ?: "the invitation ended", it.optString("details")) }
                return State(o.optLong("version") ?: version, o.optString("state") ?: "open", r, o.optString("name") ?: "", f)
            } finally {
                leave()
            }
        }

        /** The user's answer about the device that asks to join. */
        fun answer(yes: Boolean) {
            if (runCatching { enter() }.isFailure) return
            try {
                lib.cbb_invite_answer(handle, if (yes) 1 else 0)
            } finally {
                leave()
            }
        }

        private fun enter() = synchronized(lock) {
            check(!closed.get()) { "the invitation is closed" }
            calls++
        }

        private fun leave() = synchronized(lock) {
            calls--
            lock.notifyAll()
        }

        /** Ends the invitation; it waits a moment for its window to close. */
        override fun close() {
            synchronized(lock) {
                if (closed.getAndSet(true)) return
                while (calls > 0) lock.wait()
            }
            lib.cbb_invite_free(handle)
        }
    }

    /**
     * A home window of a phone of 0.6 (docs/protocol.md, "Pairing in 0.6"):
     * the member port listens, the app shows [qr] and [digits], the new
     * device dials and proves the digits; nobody is asked. public is the
     * admitting key sign holds (the admin key, or the root's); addrs the
     * phone's home addresses without a port; expiresS in seconds (five
     * minutes when 0, an hour at most). The app announces the window itself
     * with NSD (p=1, f=[fingerprint], i=[id]), never the digits.
     */
    class Window(member: CoreMember, public: ByteArray, addrs: List<String>, expiresS: Int = 0, sign: (ByteArray) -> ByteArray) : Closeable {
        private val signFn = CoreMember.signFn(sign)
        private val handle: Pointer
        private val closed = AtomicBoolean(false)
        private val lock = Object()
        private var calls = 0

        /**
         * open, joining (a device pairs), done (name joined; the window is closed), failed (that attempt; the
         * window stays open) or closed (its time is up, or three wrong codes: failure).
         */
        data class State(val version: Long, val state: String, val name: String, val device: String, val failure: Failure?)

        /**
         * The QR code's text, cbb://pair?addr=...&fp=...&i=...&c=..., the six digits to show, the window's ID
         * and the key hash it names in hex, and how long it is open, in seconds.
         */
        val qr: String
        val digits: String
        val id: String
        val fingerprint: String
        val expires: Int

        init {
            val request = Wire.encode(
                Wire.obj(
                    "public" to Wire.bytes(CoreMember.point(public)),
                    "addrs" to JsonArray(addrs.map { JsonPrimitive(it) }),
                    "expires" to JsonPrimitive(expiresS),
                    "mdns" to JsonPrimitive(false),
                ),
            )
            val answer = PointerByReference()
            val count = count()
            val h = lib.cbb_window_new(member.handle, request, Core.SizeT(request.size.toLong()), signFn, null, answer, count)
            val got = answer.value?.let { CoreMember.take(it, count) } ?: throw Core.Mismatch("the core gave no answer to the window")
            val o = try {
                ok("window", got)
            } catch (e: Exception) {
                h?.let { lib.cbb_window_free(it) }
                throw e
            }
            handle = h ?: throw Core.Mismatch("the core opened no window")
            qr = o.optString("qr") ?: ""
            digits = o.optString("digits") ?: ""
            id = o.optString("id") ?: ""
            fingerprint = o.optString("fingerprint") ?: ""
            expires = (o.optLong("expires") ?: 0).toInt()
        }

        /** Waits up to timeoutMS for a state past version; it blocks, so the app calls it off its main thread. */
        fun next(version: Long, timeoutMS: Long = 1000): State {
            enter()
            try {
                val o = ok("window", call { c -> lib.cbb_window_next(handle, version, timeoutMS, c) })
                val f = o.optObject("error")?.let { Failure(it.optString("message") ?: "the pairing failed", it.optString("details")) }
                return State(o.optLong("version") ?: version, o.optString("state") ?: "open", o.optString("name") ?: "", o.optString("device") ?: "", f)
            } finally {
                leave()
            }
        }

        private fun enter() = synchronized(lock) {
            check(!closed.get()) { "the window is closed" }
            calls++
        }

        private fun leave() = synchronized(lock) {
            calls--
            lock.notifyAll()
        }

        /** Closes the window. */
        override fun close() {
            synchronized(lock) {
                if (closed.getAndSet(true)) return
                while (calls > 0) lock.wait()
            }
            lib.cbb_window_free(handle)
        }
    }

    /**
     * A new phone that joins a group of 0.6 by a home window's QR code, or
     * by the six digits the person typed (qr "", the one window found by
     * mDNS): it dials, proves the digits, and the group is kept in dir,
     * where the app then starts its member. public is the member key sign
     * holds.
     */
    class Joiner(
        dir: String,
        qr: String,
        name: String,
        os: String,
        public: ByteArray,
        sign: (ByteArray) -> ByteArray,
        digits: String = "",
        invite: String = "",
        /** The admin key this phone offers, its public key and its signer: the root keeps it and makes the phone an admin with it later. */
        admin: Pair<ByteArray, (ByteArray) -> ByteArray>? = null,
    ) : Closeable {
        private val signFn = CoreMember.signFn(sign)
        private val adminSignFn = admin?.let { CoreMember.signFn(it.second) }
        private val handle: Pointer
        private val closed = AtomicBoolean(false)
        private val lock = Object()
        private var calls = 0

        /**
         * dialing, done (group, device, and name, the member that let the phone in) or failed; by an invitation,
         * answered once the hub answered through the guest tunnel.
         */
        data class State(
            val version: Long,
            val state: String,
            val group: String,
            val device: String,
            val name: String,
            val failure: Failure?,
            val answered: Boolean = false,
        )

        /** By an invitation ([invite], a remote invitation's text): the fingerprint the phone shows, which the inviting admin compares. */
        val fingerprint: String

        init {
            val request = Wire.encode(
                Wire.obj(
                    "dir" to Wire.str(dir),
                    "qr" to Wire.str(qr),
                    "digits" to Wire.str(digits),
                    "invite" to Wire.str(invite),
                    "name" to Wire.str(name),
                    "os" to Wire.str(os),
                    "public" to Wire.bytes(CoreMember.point(public)),
                    "admin_public" to admin?.let { Wire.bytes(CoreMember.point(it.first)) },
                ),
            )
            val answer = PointerByReference()
            val count = count()
            val n = Core.SizeT(request.size.toLong())
            val h = if (adminSignFn == null) {
                lib.cbb_joiner_new(request, n, signFn, null, answer, count)
            } else {
                lib.cbb_joiner_new_admin(request, n, signFn, null, adminSignFn, null, answer, count)
            }
            val got = answer.value?.let { CoreMember.take(it, count) } ?: throw Core.Mismatch("the core gave no answer to joining")
            val first = try {
                ok("join", got)
            } catch (e: Exception) {
                h?.let { lib.cbb_joiner_free(it) }
                throw e
            }
            handle = h ?: throw Core.Mismatch("the core started no joining")
            fingerprint = first.optString("fingerprint") ?: ""
        }

        /** Waits up to timeoutMS for a state past version; it blocks, so the app calls it off its main thread. */
        fun next(version: Long, timeoutMS: Long = 1000): State {
            enter()
            try {
                val o = ok("join", call { c -> lib.cbb_joiner_next(handle, version, timeoutMS, c) })
                val f = o.optObject("error")?.let { Failure(it.optString("message") ?: "the pairing failed", it.optString("details")) }
                return State(
                    o.optLong("version") ?: version,
                    o.optString("state") ?: "dialing",
                    o.optString("group") ?: "",
                    o.optString("device") ?: "",
                    o.optString("name") ?: "",
                    f,
                    o.optBool("answered") ?: false,
                )
            } finally {
                leave()
            }
        }

        private fun enter() = synchronized(lock) {
            check(!closed.get()) { "joining ended" }
            calls++
        }

        private fun leave() = synchronized(lock) {
            calls--
            lock.notifyAll()
        }

        /** Ends joining. */
        override fun close() {
            synchronized(lock) {
                if (closed.getAndSet(true)) return
                while (calls > 0) lock.wait()
            }
            lib.cbb_joiner_free(handle)
        }
    }

    private fun count() = Memory(Native.SIZE_T_SIZE.toLong()).apply { clear() }

    /** Calls f with the answer's length and takes the answer it returns. */
    private fun call(f: (Memory) -> Pointer?): ByteArray {
        val c = count()
        val answer = f(c) ?: throw Core.Mismatch("the core gave no answer")
        return CoreMember.take(answer, c)
    }

    /** The answer's ok; its error throws [Failure]. */
    private fun ok(what: String, bytes: ByteArray): JsonObject =
        try {
            CoreMember.okOf(what, bytes)
        } catch (e: Core.Refusal) {
            throw Failure(e.message ?: "the core refused $what", e.details)
        }

    @Suppress("FunctionName")
    private interface Lib : Library {
        fun cbb_group_new(request: ByteArray, len: Core.SizeT, sign: CoreMember.SignFn, ctx: Pointer?, answerLen: Pointer): Pointer?

        fun cbb_invite_new(m: Pointer, request: ByteArray, len: Core.SizeT, sign: CoreMember.SignFn, ctx: Pointer?, answer: PointerByReference, answerLen: Pointer): Pointer?

        fun cbb_invite_next(i: Pointer, version: Long, timeoutMS: Long, answerLen: Pointer): Pointer?

        fun cbb_invite_answer(i: Pointer, yes: Int)

        fun cbb_invite_free(i: Pointer)

        fun cbb_window_new(m: Pointer, request: ByteArray, len: Core.SizeT, sign: CoreMember.SignFn, ctx: Pointer?, answer: PointerByReference, answerLen: Pointer): Pointer?

        fun cbb_window_next(w: Pointer, version: Long, timeoutMS: Long, answerLen: Pointer): Pointer?

        fun cbb_window_free(w: Pointer)

        fun cbb_joiner_new(request: ByteArray, len: Core.SizeT, sign: CoreMember.SignFn, ctx: Pointer?, answer: PointerByReference, answerLen: Pointer): Pointer?

        fun cbb_joiner_new_admin(
            request: ByteArray,
            len: Core.SizeT,
            sign: CoreMember.SignFn,
            ctx: Pointer?,
            adminSign: CoreMember.SignFn,
            adminCtx: Pointer?,
            answer: PointerByReference,
            answerLen: Pointer,
        ): Pointer?

        fun cbb_joiner_next(j: Pointer, version: Long, timeoutMS: Long, answerLen: Pointer): Pointer?

        fun cbb_joiner_free(j: Pointer)
    }

    private val lib: Lib by lazy { Native.load("cbb_ffi", Lib::class.java) }
}
