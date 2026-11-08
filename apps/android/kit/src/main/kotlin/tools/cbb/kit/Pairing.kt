// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Base64

/**
 * The pairing messages of docs/protocol.md, section 6, encoded as the Go
 * side encodes them: JSON objects whose byte fields are standard base64,
 * in frames of a 4-byte big-endian length.
 */
object Pairing {
    /** The ALPN protocol of pairing connections. */
    const val ALPN = "cbb-pair/2"

    /** The TLS exporter label for the CPace session ID. */
    const val EXPORTER_LABEL = "EXPERIMENTAL-cbb-pair-v2"

    /** Frames larger than this are refused. */
    const val MAX_FRAME = 64 shl 10

    /** What a Welcome leaves for everything but its records, so that one with them fits in a frame. */
    const val WELCOME_ROOM = 4 shl 10

    private val CHANNEL_PREFIX = "cbb pair v2\u0000".toByteArray()

    /** One frame of the exchange; each uses some of the fields. */
    class Frame(
        val msg: ByteArray? = null,
        val ad: ByteArray? = null,
        val tag: ByteArray? = null,
        val welcome: Welcome? = null,
        val error: String? = null,
        val ok: Boolean? = null,
    ) {
        fun toJson(): JsonObject = Wire.obj(
            "msg" to Wire.bytes(msg),
            "ad" to Wire.bytes(ad),
            "tag" to Wire.bytes(tag),
            "welcome" to welcome?.toJson(),
            "error" to Wire.str(error),
            "ok" to ok?.let { JsonPrimitive(it) },
        )

        companion object {
            fun fromJson(o: JsonObject): Frame = Frame(
                msg = o.optBytes("msg"),
                ad = o.optBytes("ad"),
                tag = o.optBytes("tag"),
                welcome = o.optObject("welcome")?.let { Welcome.fromJson(it) },
                error = o.optString("error"),
                ok = o.opt("ok")?.let { (it as? JsonPrimitive)?.takeIf { p -> !p.isString }?.booleanOrNull ?: throw WireTypeException("ok") },
            )
        }
    }

    /**
     * What a new device receives: its member certificate, the group CA
     * and, for a Linux device in a group rooted in a Linux member, the CA
     * keys. A phone root never sends keys; it may send a joining phone its
     * admin CA.
     */
    class Welcome(
        val cert: ByteArray,
        /** The group's first root, which names it. */
        val groupCA: ByteArray,
        /** The admin CA that issued cert and the admitting phone's own certificate; null when the group CA did. */
        val issuer: ByteArray? = null,
        /** For a phone that joins as an admin: the admin CA the root issued for the admin key the phone sent in its Info. */
        val adminCA: ByteArray? = null,
        /** The roots that took a phone group over from groupCA, in order; null when it was never handed over (section 10, "Roots"). */
        val roots: List<ByteArray>? = null,
        /** The group's records (RecordSet.pathRecords), by which the joiner checks the roots and takes its peers at once. */
        val records: List<Member.Record>? = null,
        /** When the admitting member first held each claim, so the new member counts the claims' delays as it does. */
        val claimTimes: List<RecordSet.ClaimTime>? = null,
    ) {
        fun toJson(): JsonObject = Wire.obj(
            "cert" to Wire.bytes(cert),
            "issuer" to Wire.bytes(issuer),
            "group_ca" to Wire.bytes(groupCA),
            "roots" to Wire.list(roots),
            "records" to records?.let { rs -> kotlinx.serialization.json.JsonArray(rs.map { it.toJson() }) },
            "admin_ca" to Wire.bytes(adminCA),
            "claim_times" to claimTimes?.let { ts -> kotlinx.serialization.json.JsonArray(ts.map { it.toJson() }) },
        )

        companion object {
            fun fromJson(o: JsonObject): Welcome = Welcome(
                cert = o.optBytes("cert") ?: throw WireTypeException("welcome without cert"),
                groupCA = o.optBytes("group_ca") ?: throw WireTypeException("welcome without group_ca"),
                issuer = o.optBytes("issuer"),
                adminCA = o.optBytes("admin_ca"),
                roots = o.optBytesList("roots"),
                records = o.optArray("records")?.map { Member.Record.fromJson(it as? JsonObject ?: throw WireTypeException("a record is not an object")) },
                claimTimes = o.optArray("claim_times")?.let { RecordSet.ClaimTime.list(it) },
            )
        }
    }

    /** The joiner's CPace associated data. */
    data class Info(
        val name: String,
        /** "linux", "windows", "macos", "ios" for an iPhone with the app, "android", "aurora", "sailfish", or "none" for a lite member's firmware. */
        val os: String,
        /** A phone's admin key, a SubjectPublicKeyInfo, for the admin CA the root may issue it; only from a phone. */
        val adminKey: ByteArray? = null,
        /** LITE for a lite member, which only dials and never holds CA keys; null for a full device. */
        val role: String? = null,
        /** The joiner's public key for sealed messages, which the phone that admits it puts in its device record (docs/protocol.md, section 15). */
        val seal: ByteArray? = null,
        /** The admin key's signature (ECDSA with SHA-256, DER) over adminProofMessage of this connection's session ID; it comes with adminKey. */
        val adminProof: ByteArray? = null,
    ) {
        /** This description with the admin key's proof for sessionID, signed by admin, the key adminKey names. */
        fun proving(sessionID: ByteArray, admin: CertificateSigner): Info =
            if (adminKey == null) this else copy(adminProof = admin.signature(adminProofMessage(sessionID)))

        /** Whether adminProof is adminKey's signature for sessionID. */
        fun provesAdminKey(sessionID: ByteArray): Boolean {
            val k = adminKey ?: return false
            val p = adminProof ?: return false
            return verifySignature(k, adminProofMessage(sessionID), p)
        }

        /**
         * Checks it as the member does: a known OS, a printable name of 1
         * to 64 bytes, a known role, and an admin key only from a phone, a
         * P-256 one.
         */
        val isValid: Boolean
            get() {
                if ((os !in OSES && !(os == "none" && role == LITE)) || name.isEmpty() || name.toByteArray().size > 64 || !printable(name)) return false
                if (role != null && role != LITE) return false
                if (seal != null && seal.size != SEAL_KEY_SIZE) return false
                if ((adminKey == null) != (adminProof == null)) return false
                val k = adminKey ?: return true
                return isPhone(os) && p256PublicKey(k) != null
            }

        fun encode(): ByteArray = Wire.encode(Wire.obj("name" to Wire.str(name), "os" to Wire.str(os), "admin_key" to Wire.bytes(adminKey), "admin_proof" to Wire.bytes(adminProof), "role" to Wire.str(role), "seal" to Wire.bytes(seal)))

        override fun equals(other: Any?): Boolean =
            other is Info && name == other.name && os == other.os && adminKey.contentEqualsOrNull(other.adminKey) && role == other.role &&
                seal.contentEqualsOrNull(other.seal) && adminProof.contentEqualsOrNull(other.adminProof)

        override fun hashCode(): Int = name.hashCode()

        companion object {
            val OSES = setOf("linux", "windows", "macos", "ios", "android", "aurora", "sailfish")

            /** The role of a lite member. */
            const val LITE = "lite"

            /** The size of a key for sealed messages (an X-Wing public key). */
            const val SEAL_KEY_SIZE = 1216

            /** What the admin key signs to prove the phone holds it: the label, a zero byte and sessionID, the TLS exporter's output (docs/protocol.md, section 6). */
            fun adminProofMessage(sessionID: ByteArray): ByteArray = "cbb pairing admin key".toByteArray() + byteArrayOf(0) + sessionID

            /** Whether a joiner's OS is a phone's, which joins as a phone and may become an admin. */
            fun isPhone(os: String): Boolean = os in PHONE_OSES

            /** The systems of phones with the app. */
            val PHONE_OSES = setOf("ios", "android", "aurora", "sailfish")

            fun decode(data: ByteArray): Info? {
                val o = Wire.parse(data) ?: return null
                return try {
                    Info(o.optString("name") ?: return null, o.optString("os") ?: return null, o.optBytes("admin_key"), o.optString("role"), o.optBytes("seal"), o.optBytes("admin_proof"))
                } catch (e: WireTypeException) {
                    null
                }
            }
        }
    }

    /** The member's CPace associated data. */
    data class MemberAD(val device: String, val group: String) {
        fun encode(): ByteArray = Wire.encode(Wire.obj("device" to Wire.str(device), "group" to Wire.str(group)))

        companion object {
            fun decode(data: ByteArray): MemberAD? {
                val o = Wire.parse(data) ?: return null
                return try {
                    MemberAD(o.optString("device") ?: return null, o.optString("group") ?: return null)
                } catch (e: WireTypeException) {
                    null
                }
            }
        }
    }

    /** The error codes that travel in frames. Anything else means "refused". */
    enum class ErrorCode(val wire: String) {
        WRONG_CODE("wrong-code"), CLOSED("closed"), BUSY("busy"), EXPIRED("expired"), TOO_MANY("too-many"), TAKEN("taken"), DECLINED("declined"), REFUSED("refused");

        companion object {
            fun of(wire: String): ErrorCode = entries.firstOrNull { it.wire == wire } ?: REFUSED
        }
    }

    class FrameException(message: String) : Exception(message)

    /** The CPace channel identifier: the prefix, then SHA-256 of the member's and the joiner's certificate, in that order. */
    fun channelID(memberCert: ByteArray, joinerCert: ByteArray): ByteArray = CHANNEL_PREFIX + sha256(memberCert) + sha256(joinerCert)

    /**
     * The fingerprint of a certificate's key, the one form of docs/protocol.md (Conventions, "Fingerprints"):
     * SHA-256 over its SubjectPublicKeyInfo in standard base64, as a record's key hash; empty for bytes that
     * are no certificate. A join QR code carries it.
     */
    fun fingerprint(cert: ByteArray): String =
        runCatching { CertificateInfo(cert).publicKey }.getOrNull()?.let { Base64.getEncoder().encodeToString(sha256(it)) } ?: ""

    /** Encodes a frame: the length, then the JSON. */
    fun encode(f: Frame): ByteArray {
        val body = Wire.encode(f.toJson())
        if (body.size > MAX_FRAME) throw FrameException("frame too large")
        return Member.frame(body)
    }

    /** Decodes the body of a frame whose length was read already. */
    fun decode(body: ByteArray): Frame {
        val o = Wire.parse(body) ?: throw FrameException("not a frame")
        return try {
            Frame.fromJson(o)
        } catch (e: WireTypeException) {
            throw FrameException("not a frame: ${e.message}")
        }
    }

    /** The length a frame header announces, or an error when too large. */
    fun length(header: ByteArray): Int =
        try {
            Member.length(header, MAX_FRAME)
        } catch (e: Member.WireException) {
            throw FrameException(e.message ?: "bad frame header")
        }

    /**
     * Whether every character of s may be in a name, as Go's unicode.IsPrint
     * says: a letter, mark, number, punctuation, symbol or the ASCII space; no
     * control, format, private-use, unassigned or other space.
     */
    internal fun printable(s: String): Boolean =
        s.codePoints().allMatch { cp ->
            cp == ' '.code ||
                when (Character.getType(cp).toByte()) {
                    Character.UPPERCASE_LETTER, Character.LOWERCASE_LETTER, Character.TITLECASE_LETTER,
                    Character.MODIFIER_LETTER, Character.OTHER_LETTER,
                    Character.NON_SPACING_MARK, Character.COMBINING_SPACING_MARK, Character.ENCLOSING_MARK,
                    Character.DECIMAL_DIGIT_NUMBER, Character.LETTER_NUMBER, Character.OTHER_NUMBER,
                    Character.CONNECTOR_PUNCTUATION, Character.DASH_PUNCTUATION, Character.START_PUNCTUATION,
                    Character.END_PUNCTUATION, Character.INITIAL_QUOTE_PUNCTUATION, Character.FINAL_QUOTE_PUNCTUATION,
                    Character.OTHER_PUNCTUATION,
                    Character.MATH_SYMBOL, Character.CURRENCY_SYMBOL, Character.MODIFIER_SYMBOL, Character.OTHER_SYMBOL,
                    -> true
                    else -> false
                }
        }
}

/**
 * What the QR code of cbb pair carries (docs/protocol.md, section 7):
 * cbb://join?code=123456&addr=host:port&fp=...
 */
data class JoinCode(val code: String, val addrs: List<String>, val fingerprint: String) {
    /** Whether the code is six digits, as the computer expects. */
    val codeIsValid: Boolean get() = code.length == 6 && code.all { it in '0'..'9' }

    /** The code as the screen shows it, in two groups of three digits, for a computer of the group to type. */
    val grouped: String get() = if (code.length == 6) code.substring(0, 3) + " " + code.substring(3) else code

    /** The text of the QR code, as cbb pair shows it. */
    val qrText: String
        get() {
            val items = listOf("code" to code) + addrs.take(MAX_ADDRS).map { "addr" to it } + listOf("fp" to fingerprint)
            return "cbb://join?" + items.joinToString("&") { "${it.first}=${escape(it.second)}" }
        }

    companion object {
        /** At most this many addresses are kept. */
        const val MAX_ADDRS = 4

        /**
         * Parses the text of a join QR code; null when it is not one. Unknown
         * fields are ignored, and addresses without a port are dropped.
         */
        fun parse(text: String): JoinCode? {
            val t = text.trim()
            val sep = t.indexOf("://")
            if (sep < 0 || !t.substring(0, sep).equals("cbb", ignoreCase = true)) return null
            val rest = t.substring(sep + 3).substringBefore('#')
            val host = rest.takeWhile { it != '/' && it != '?' }
            if (!host.equals("join", ignoreCase = true)) return null
            val query = rest.substringAfter('?', "")
            val items = query.split('&').filter { it.isNotEmpty() }.mapNotNull { item ->
                val k = unescape(item.substringBefore('=')) ?: return@mapNotNull null
                val v = unescape(item.substringAfter('=', "")) ?: return@mapNotNull null
                k to v
            }
            val code = items.firstOrNull { it.first == "code" }?.second
            if (code.isNullOrEmpty()) return null
            val fp = items.firstOrNull { it.first == "fp" }?.second ?: ""
            val addrs = items.filter { it.first == "addr" }.map { it.second }.filter { hasPort(it) }.take(MAX_ADDRS)
            return JoinCode(code, addrs, fp)
        }

        /** Whether a host:port, or [IPv6]:port, has a port. */
        internal fun hasPort(a: String): Boolean {
            val i = a.lastIndexOf(':')
            if (i < 0) return false
            val port = a.substring(i + 1).toIntOrNull() ?: return false
            if (port !in 1..65535 || !a.substring(i + 1).all { it in '0'..'9' }) return false
            val host = a.substring(0, i)
            if (host.startsWith("[")) return host.endsWith("]")
            return host.isNotEmpty() && ':' !in host
        }

        /** Whether a host:port, or [IPv6]:port, is on a home network: a private IPv4 or unique local IPv6 address. */
        fun isHome(a: String): Boolean {
            if (!hasPort(a)) return false
            val host = a.substring(0, a.lastIndexOf(':'))
            return if (host.startsWith("[")) LocalAddresses.isHomeIPv6(host.substring(1, host.length - 1)) else LocalAddresses.isHomeIPv4(host)
        }

        private val random = SecureRandom()

        /** A new six-digit code. */
        fun newCode(): String = "%06d".format(random.nextInt(1_000_000))

        /** host:port, or [IPv6]:port, as a QR code carries an address. */
        fun address(host: String, port: Int): String = if (':' in host) "[$host]:$port" else "$host:$port"

        /** Percent-decoding, as URL components decode a query; null for a bad escape or bad UTF-8. */
        private fun unescape(s: String): String? {
            val b = s.toByteArray()
            val out = ByteArrayOutputStream()
            var i = 0
            while (i < b.size) {
                if (b[i] == '%'.code.toByte()) {
                    if (i + 2 >= b.size) return null
                    val h = String(b, i + 1, 2, Charsets.US_ASCII).toIntOrNull(16) ?: return null
                    out.write(h)
                    i += 3
                } else {
                    out.write(b[i].toInt())
                    i++
                }
            }
            val bytes = out.toByteArray()
            val decoded = String(bytes, Charsets.UTF_8)
            return if (decoded.toByteArray().contentEquals(bytes)) decoded else null
        }

        private fun escape(s: String): String {
            val sb = StringBuilder()
            for (byte in s.toByteArray()) {
                val c = byte.toInt() and 0xff
                val ch = c.toChar()
                if (ch in 'a'..'z' || ch in 'A'..'Z' || ch in '0'..'9' || ch in "-._~") sb.append(ch) else sb.append("%%%02X".format(c))
            }
            return sb.toString()
        }
    }
}
