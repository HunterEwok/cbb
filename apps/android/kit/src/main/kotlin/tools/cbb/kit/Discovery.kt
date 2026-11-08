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
    /** Whether a computer pairing window is open (`p=1`). */
    val pairing: Boolean = false,
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
        return FoundMember(instance, fields["g"], fields["p"] == "1")
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
     * The members to dial: those browsing found, and the devices of the
     * group with a known address that it did not find, as a member in
     * another subnet, which mDNS does not reach (docs/protocol.md, section 9).
     */
    fun withKnown(found: Set<FoundMember>, known: Set<String>, group: String): Set<FoundMember> =
        found + known.filter { d -> found.none { it.device == d } }.map { FoundMember(it, group) }
}
