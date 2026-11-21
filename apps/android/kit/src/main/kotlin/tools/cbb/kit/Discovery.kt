// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

/**
 * A Linux member found by mDNS browsing (docs/protocol.md, section 3): its
 * device ID, the first label of its service instance, and what its TXT
 * record says.
 */
data class FoundMember(
    val device: String,
    /** The group tag (`g`); null when the TXT record has none. */
    val group: String?,
    /** Whether a pairing window is open (`p=1`). */
    val pairing: Boolean = false,
    /** A home window's ID in hex (`i`), beside `p=1`; null when none is announced. */
    val windowID: String? = null,
    /** The hash of the window's member key in hex (`f`); null when none is announced. */
    val fingerprint: String? = null,
)

object Discovery {
    /** The DNS-SD service type the Linux members publish. */
    const val SERVICE_TYPE = "_cbb._tcp"

    /**
     * Reads a found service: the instance name must be a device ID; the TXT
     * strings are "key=value", keys matched without regard to case, the
     * value what follows the first "=". Unknown keys are ignored.
     */
    fun member(instance: String, txt: List<String>): FoundMember? {
        if (!GroupCertificates.isDeviceID(instance)) return null
        val fields = mutableMapOf<String, String>()
        for (s in txt) {
            val i = s.indexOf('=')
            val k = (if (i < 0) s else s.substring(0, i)).lowercase()
            val v = if (i < 0) "" else s.substring(i + 1)
            fields.putIfAbsent(k, v)
        }
        return FoundMember(instance, fields["g"], fields["p"] == "1", fields["i"]?.takeIf { it.isNotEmpty() }, fields["f"]?.takeIf { it.isNotEmpty() })
    }

    /** The same from a TXT record already split into keys and values, as Android's NsdServiceInfo gives it. */
    fun member(instance: String, txt: Map<String, ByteArray?>): FoundMember? =
        member(instance, txt.map { (k, v) -> "$k=${v?.toString(Charsets.UTF_8) ?: ""}" })

    /**
     * The TXT record of a device that waits to join, listening with its QR
     * code on screen: no group tag, so no member dials it, and the
     * fingerprint of its certificate, which a computer of the group checks
     * when it admits the device by the code typed there (docs/protocol.md,
     * sections 3 and 6).
     */
    fun joinerTXT(fingerprint: String): Map<String, String> = mapOf("v" to "1", "j" to "1", "f" to fingerprint)

    /**
     * The TXT record of a phone's open home window of 0.6: v=1, the
     * group's tag, p=1, the hash of the member key and the window's ID the
     * window's QR code names, never its digits, so that a device whose
     * person types the digits finds it (docs/protocol.md, "Pairing in 0.6").
     */
    fun windowTXT(group: String, fingerprint: String, id: String): Map<String, String> =
        mapOf("v" to "1", "g" to group, "p" to "1", "f" to fingerprint, "i" to id)

    /**
     * The QR code text of a home window found by mDNS, at address
     * (host:port, an IPv6 host in brackets), with the six digits the person
     * typed: cbb://pair?addr=...&fp=...&i=...&c=..., as the core reads it.
     */
    fun windowLink(address: String, fingerprint: String, id: String, digits: String): String {
        val addr = buildString {
            for (b in address.toByteArray(Charsets.UTF_8)) {
                val c = b.toInt() and 0xff
                if ((c < 0x80 && c.toChar().isLetterOrDigit()) || "-._~:[]".indexOf(c.toChar()) >= 0) append(c.toChar()) else append("%%%02X".format(c))
            }
        }
        return "cbb://pair?addr=$addr&fp=$fingerprint&i=$id&c=$digits"
    }

    /**
     * The members to dial: those browsing found, and the devices of the
     * group with a known address that it did not find, as a member in
     * another subnet, which mDNS does not reach (docs/protocol.md, section 9).
     */
    fun withKnown(found: Set<FoundMember>, known: Set<String>, group: String): Set<FoundMember> =
        found + known.filter { d -> found.none { it.device == d } }.map { FoundMember(it, group) }
}
