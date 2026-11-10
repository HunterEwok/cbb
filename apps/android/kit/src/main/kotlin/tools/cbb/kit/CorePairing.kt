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
import java.io.IOException
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Pairing in the Rust core (docs/core-api.md, "Joining and admitting"):
 * a phone that makes a group ([newGroup]), joins one by its QR code as the
 * joiner that listens ([Joining]), or admits a device by the device's QR
 * code as an admin ([Admitting]). The core runs the exchange inside its own
 * TLS and asks for each signature through a callback, so the keys stay in
 * the Keystore; the app does the sockets and hands each connection to
 * these classes, which pass its bytes to the core until the exchange ends.
 */
object CorePairing {
    /** Why a pairing failed: the core's message and details, and whether the code was wrong. */
    class Failure(message: String, val details: String? = null, val wrongCode: Boolean = false) : Exception(message) {
        override fun toString(): String = "CorePairing.Failure: $message" + (details?.takeIf { it.isNotEmpty() }?.let { "\n$it" } ?: "")
    }

    /**
     * A group this phone is in, as the core made or joined it: its device
     * ID, member certificate and the admin CA that issued it, the group CA,
     * the later roots, the records file and, for a phone made an admin, its
     * admin CA.
     */
    class Group(
        val device: String,
        val cert: ByteArray,
        val issuer: ByteArray?,
        val groupCA: ByteArray,
        val roots: List<ByteArray>,
        val records: ByteArray,
        val adminCA: ByteArray?,
    ) {
        internal companion object {
            fun of(o: JsonObject): Group = Group(
                o.optString("device") ?: throw Core.Mismatch("the group has no device"),
                o.optBytes("cert") ?: throw Core.Mismatch("the group has no certificate"),
                o.optBytes("issuer"),
                o.optBytes("group_ca") ?: throw Core.Mismatch("the group has no group CA"),
                o.optBytesList("roots").orEmpty(),
                o.optBytes("records") ?: ByteArray(0),
                o.optBytes("admin_ca"),
            )
        }
    }

    /**
     * Makes a group with this phone's root key (cbb_group_new): its root CA,
     * this phone's member certificate and its device record. rootPublic and
     * public are the root and member keys (SubjectPublicKeyInfo or point),
     * store where the member key lives (Records.HARDWARE or Records.FILE),
     * seal the phone's public key for sealed messages; signRoot signs a
     * digest with the root key, during this call only.
     */
    fun newGroup(name: String, os: String, store: String, rootPublic: ByteArray, public: ByteArray, seal: ByteArray?, signRoot: (ByteArray) -> ByteArray): Group {
        val request = Wire.encode(
            Wire.obj(
                "name" to Wire.str(name),
                "os" to Wire.str(os),
                "store" to Wire.str(store),
                "root_public" to Wire.bytes(CoreMember.point(rootPublic)),
                "public" to Wire.bytes(CoreMember.point(public)),
                "seal" to Wire.bytes(seal),
            ),
        )
        val sign = CoreMember.signFn(signRoot)
        val count = count()
        val answer = lib.cbb_group_new(request, Core.SizeT(request.size.toLong()), sign, null, count)
            ?: throw Core.Mismatch("the core gave no answer to the new group")
        return Group.of(ok("new group", CoreMember.take(answer, count)))
    }

    /**
     * Runs one connection's exchange: sends what the core gives, reads what
     * comes and hands it in, until done says the exchange ended. A connection
     * that closes before then fails.
     */
    private fun exchange(socket: Socket, first: ByteArray, feed: (ByteArray) -> Pair<ByteArray, Boolean>) {
        val out = socket.getOutputStream()
        val input = socket.getInputStream()
        if (first.isNotEmpty()) out.write(first)
        out.flush()
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) throw IOException("the connection closed during pairing")
            val (send, done) = feed(buf.copyOf(n))
            if (send.isNotEmpty()) {
                out.write(send)
                out.flush()
            }
            if (done) return
        }
    }

    /**
     * Joining a group as the joiner that listens (docs/protocol.md, section
     * 6): makes the device ID, the code and the QR code for addrs, the
     * addresses the app listens on, and takes each connection the app
     * accepts with [attempt] until an admin admits this phone. With
     * adminPublic and signAdmin the phone offers an admin key, whose
     * proof the core signs on the connection. With invite, a remote
     * invitation's text (docs/protocol.md, section 12), the phone joins by
     * it in place of showing a QR code: the core starts the invitation's
     * guest tunnel, the app dials 127.0.0.1:[port] and runs [attempt]
     * there, and the hub's admin admits the phone by its fingerprint.
     */
    class Joining(
        name: String,
        os: String,
        public: ByteArray,
        seal: ByteArray?,
        addrs: List<String>,
        sign: (ByteArray) -> ByteArray,
        adminPublic: ByteArray? = null,
        signAdmin: ((ByteArray) -> ByteArray)? = null,
        code: String = "",
        invite: String? = null,
    ) : Closeable {
        private val signFn = CoreMember.signFn(sign)
        private val adminFn = signAdmin?.let { CoreMember.signFn(it) }
        private val handle: Pointer
        private val closed = AtomicBoolean(false)

        /** This phone's device ID, the six-digit code, the certificate's fingerprint and the QR code's text. */
        val device: String
        val code: String
        val fingerprint: String
        val qr: String

        /** With an invitation: the loopback port of its guest tunnel. */
        val port: Int

        /** Whether the invitation's hub has answered through the guest tunnel: an attempt that failed before it did says the hub is off or cannot be reached. */
        val answered: Boolean get() = !closed.get() && lib.cbb_join_answered(handle) == 1

        init {
            require((adminPublic == null) == (signAdmin == null)) { "the admin key needs both its public key and its signer" }
            val request = Wire.encode(
                Wire.obj(
                    "name" to Wire.str(name),
                    "os" to Wire.str(os),
                    "public" to Wire.bytes(CoreMember.point(public)),
                    "admin_public" to Wire.bytes(adminPublic?.let { CoreMember.point(it) }),
                    "seal" to Wire.bytes(seal),
                    "addrs" to JsonArray(addrs.map { JsonPrimitive(it) }),
                    "code" to Wire.str(code),
                    "invite" to invite?.let { Wire.str(it) },
                ),
            )
            val answer = PointerByReference()
            val count = count()
            val len = Core.SizeT(request.size.toLong())
            val h = if (adminFn == null) {
                lib.cbb_join_new(request, len, signFn, null, answer, count)
            } else {
                lib.cbb_join_new_admin(request, len, signFn, null, adminFn, null, answer, count)
            }
            val got = answer.value?.let { CoreMember.take(it, count) } ?: throw Core.Mismatch("the core gave no answer to the join")
            val o = ok("join", got)
            handle = h ?: throw Core.Mismatch("the core made no joiner")
            device = o.optString("device") ?: ""
            this.code = o.optString("code") ?: ""
            fingerprint = o.optString("fingerprint") ?: ""
            qr = o.optString("qr") ?: ""
            port = (o.optLong("port") ?: 0).toInt()
        }

        /**
         * Runs the exchange on a connection the app accepted. Returns the
         * group when an admin admitted this phone, after save stored it
         * (true when it did, which the core tells the admin); a failure
         * throws [Failure], with wrongCode for a wrong code, and a dropped
         * connection IOException.
         */
        fun attempt(socket: Socket, save: (Group) -> Boolean): Group {
            check(!closed.get()) { "the joiner is closed" }
            // With an invitation, the phone speaks first: the TLS client hello.
            val started = ok("join", call { c -> lib.cbb_join_accept(handle, c) })
            var joined: Group? = null
            var failed: Failure? = null
            exchange(socket, started.optBytes("send") ?: ByteArray(0)) { data ->
                val step = ok("join", call { c -> lib.cbb_join_feed(handle, data, Core.SizeT(data.size.toLong()), 0, c) })
                val send = step.optBytes("send") ?: ByteArray(0)
                when (step.optString("state")) {
                    "joined" -> {
                        val g = Group.of(step.optObject("joined") ?: throw Core.Mismatch("the join has no group"))
                        val saved = runCatching { save(g) }.getOrDefault(false)
                        val last = ok("join", call { c -> lib.cbb_join_finish(handle, if (saved) 1 else 0, c) })
                        joined = g.takeIf { saved }
                        (send + (last.optBytes("send") ?: ByteArray(0))) to true
                    }
                    "failed" -> {
                        // The refusal goes out first, so the admin hears why.
                        failed = failure(step)
                        send to true
                    }
                    else -> send to false
                }
            }
            failed?.let { throw it }
            return joined ?: throw Failure("the group could not be saved")
        }

        override fun close() {
            if (!closed.getAndSet(true)) lib.cbb_join_free(handle)
        }
    }

    /** A device the core admitted: its ID, name, system, role ("member" or "phone"), whether it became an admin, and whether it said it stored its identity. */
    data class Admitted(val device: String, val name: String, val os: String, val role: String, val admin: Boolean, val confirmed: Boolean)

    /**
     * Admitting a device by its QR code as an admin (docs/protocol.md,
     * section 6, "The joiner listens"), through member, the phone's running
     * member, whose records the device's record joins. public is the key
     * sign holds: the admin key with adminCA, or the root's key without;
     * makeAdmin, for the root only, makes a phone that offers an admin key
     * an admin. [addrs] are the QR code's addresses, which the app dials and
     * hands to [admit] one at a time.
     */
    class Admitting(member: CoreMember, qr: String, public: ByteArray, adminCA: ByteArray?, makeAdmin: Boolean, sign: (ByteArray) -> ByteArray) : Closeable {
        private val signFn = CoreMember.signFn(sign)
        private val handle: Pointer
        private val closed = AtomicBoolean(false)

        /** The addresses of the QR code, host:port, in its order. */
        val addrs: List<String>

        init {
            val request = Wire.encode(
                Wire.obj(
                    "qr" to Wire.str(qr),
                    "public" to Wire.bytes(CoreMember.point(public)),
                    "admin_ca" to Wire.bytes(adminCA),
                    "make_admin" to JsonPrimitive(makeAdmin),
                ),
            )
            val answer = PointerByReference()
            val count = count()
            val h = lib.cbb_admit_new(member.handle, request, Core.SizeT(request.size.toLong()), signFn, null, answer, count)
            val got = answer.value?.let { CoreMember.take(it, count) } ?: throw Core.Mismatch("the core gave no answer to the admission")
            val o = ok("admit", got)
            handle = h ?: throw Core.Mismatch("the core made no admission")
            addrs = o.optArray("addrs").orEmpty().mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
        }

        /**
         * Runs the exchange on a connection the app dialed to one of addrs.
         * Returns the admitted device; a refusal throws [Failure], with
         * wrongCode for a wrong code, and a dropped connection IOException.
         * Once the device is admitted its record is in the group, whatever
         * the rest of the exchange does.
         */
        fun admit(socket: Socket): Admitted {
            check(!closed.get()) { "the admission is closed" }
            var device: JsonObject? = null
            var confirmed = false
            var failed: Failure? = null
            fun step(o: JsonObject): Pair<ByteArray, Boolean> {
                val send = o.optBytes("send") ?: ByteArray(0)
                return when (o.optString("state")) {
                    "admitted" -> {
                        device = o.optObject("device")
                        send to false
                    }
                    "done" -> {
                        confirmed = o.optBool("confirmed") ?: false
                        send to true
                    }
                    "failed" -> {
                        // The device is in the group once admitted; only its answer is missing.
                        if (device == null) failed = failure(o)
                        send to true
                    }
                    else -> send to false
                }
            }
            val first = ok("admit", call { c -> lib.cbb_admit_dial(handle, c) })
            val (hello, ended) = step(first)
            if (!ended) {
                exchange(socket, hello) { data -> step(ok("admit", call { c -> lib.cbb_admit_feed(handle, data, Core.SizeT(data.size.toLong()), 0, c) })) }
            }
            failed?.let { throw it }
            val d = device ?: throw Failure("the device was not admitted")
            return Admitted(
                d.optString("device") ?: "",
                d.optString("name") ?: "",
                d.optString("os") ?: "",
                d.optString("role") ?: "member",
                d.optBool("admin") ?: false,
                confirmed,
            )
        }

        override fun close() {
            if (!closed.getAndSet(true)) lib.cbb_admit_free(handle)
        }
    }

    /**
     * A remote invitation an admin phone makes (docs/protocol.md, section
     * 12) through member: its guest tunnel opens on this phone when it is
     * the group's hub, else through a connected hub of the group (hub
     * names one, "" for any). public is the key sign holds, as for
     * [Admitting]; sign is called when a device the user confirmed is
     * admitted. expiresS is in seconds: an hour when 0, a day at most. It
     * waits for the hub, so the app makes it off its main thread.
     */
    class Inviting(member: CoreMember, public: ByteArray, adminCA: ByteArray?, expiresS: Int, hub: String = "", sign: (ByteArray) -> ByteArray) : Closeable {
        private val signFn = CoreMember.signFn(sign)
        private val handle: Pointer
        private val closed = AtomicBoolean(false)
        private val lock = Object()
        private var calls = 0

        /** A device that proved the invitation's secret: the app asks the user whether its fingerprint matches what the device shows. */
        data class Request(val device: String, val name: String, val os: String, val fingerprint: String)

        /** Where the invitation is: open, joining (answer about request), done (name joined) or failed. */
        data class State(val version: Long, val state: String, val request: Request?, val name: String, val failure: Failure?)

        /** The invitation's text, cbb://invite#..., for its QR code, and how long it is valid, in seconds. */
        val text: String
        val expires: Int

        init {
            val request = Wire.encode(
                Wire.obj(
                    "public" to Wire.bytes(CoreMember.point(public)),
                    "admin_ca" to Wire.bytes(adminCA),
                    "expires" to JsonPrimitive(expiresS),
                    "hub" to Wire.str(hub),
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

    /** The failure a failed step names. */
    private fun failure(step: JsonObject): Failure {
        val e = step.optObject("error")
        return Failure(e?.optString("message") ?: "the pairing failed", e?.optString("details"), step.optBool("wrong_code") ?: false)
    }

    @Suppress("FunctionName")
    private interface Lib : Library {
        fun cbb_group_new(request: ByteArray, len: Core.SizeT, sign: CoreMember.SignFn, ctx: Pointer?, answerLen: Pointer): Pointer?

        fun cbb_join_new(request: ByteArray, len: Core.SizeT, sign: CoreMember.SignFn, ctx: Pointer?, answer: PointerByReference, answerLen: Pointer): Pointer?

        fun cbb_join_new_admin(
            request: ByteArray,
            len: Core.SizeT,
            sign: CoreMember.SignFn,
            ctx: Pointer?,
            adminSign: CoreMember.SignFn,
            adminCtx: Pointer?,
            answer: PointerByReference,
            answerLen: Pointer,
        ): Pointer?

        fun cbb_join_accept(j: Pointer, answerLen: Pointer): Pointer?

        fun cbb_join_feed(j: Pointer, data: ByteArray, len: Core.SizeT, nowMS: Long, answerLen: Pointer): Pointer?

        fun cbb_join_finish(j: Pointer, saved: Int, answerLen: Pointer): Pointer?

        fun cbb_join_answered(j: Pointer): Int

        fun cbb_join_free(j: Pointer)

        fun cbb_admit_new(m: Pointer, request: ByteArray, len: Core.SizeT, sign: CoreMember.SignFn, ctx: Pointer?, answer: PointerByReference, answerLen: Pointer): Pointer?

        fun cbb_admit_dial(a: Pointer, answerLen: Pointer): Pointer?

        fun cbb_admit_feed(a: Pointer, data: ByteArray, len: Core.SizeT, nowMS: Long, answerLen: Pointer): Pointer?

        fun cbb_admit_free(a: Pointer)

        fun cbb_invite_new(m: Pointer, request: ByteArray, len: Core.SizeT, sign: CoreMember.SignFn, ctx: Pointer?, answer: PointerByReference, answerLen: Pointer): Pointer?

        fun cbb_invite_next(i: Pointer, version: Long, timeoutMS: Long, answerLen: Pointer): Pointer?

        fun cbb_invite_answer(i: Pointer, yes: Int)

        fun cbb_invite_free(i: Pointer)
    }

    private val lib: Lib by lazy { Native.load("cbb_ffi", Lib::class.java) }
}
