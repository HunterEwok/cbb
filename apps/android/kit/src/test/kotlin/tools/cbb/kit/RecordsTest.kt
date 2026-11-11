// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RecordsTest {
    private val now = Instant.now()

    /** A phone's group with a computer it admitted. */
    private class Group(now: Instant) {
        val ca = SoftwareSigner()
        val g = PhoneGroup.create(ca, SoftwareSigner().publicKeyDER, now, "My\u0007phone")
        val pc = SyncEngine.newID()
        val cert = GroupCertificates.member(pc, SoftwareSigner().publicKeyDER, g.groupCA, ca, now)

        init {
            g.computers.add(PhoneGroup.Computer(pc, "pi", "linux", cert, now))
            g.record(pc, "pi", "member", Records.keyHashOfCert(cert), ca, now, caps = Records.CAPS)
        }
    }

    @Test
    fun devicesAndRevoke() {
        val x = Group(now)
        val g = x.g
        assertEquals(listOf("Myphone", "pi"), g.devices.map { it.name })
        assertEquals("phone", g.devices.first { it.id == g.device }.role)
        assertEquals(g.device, g.records.rootDevice)
        val digest = assertNotNull(g.records.digest)
        assertFailsWith<PhoneGroup.Failure> { g.revoke(g.device, x.ca, now) }
        assertFailsWith<PhoneGroup.Failure> { g.revoke(SyncEngine.newID(), x.ca, now) }
        g.revoke(x.pc, x.ca, now)
        assertEquals(listOf(g.device), g.devices.map { it.id })
        assertTrue(g.computers.isEmpty())
        assertNotEquals(digest, g.records.digest)
        assertEquals("the device was removed from the group", g.records.refused(listOf(x.cert)))

        val kept = RecordSet.fromJson(g.records.toJson())
        assertEquals(g.records.digest, kept.digest)
        assertContentEquals(g.groupCA, kept.groupCA)
    }

    /**
     * A device ID whose records name two keys stays listed while either is
     * not revoked, and removing it revokes both, as Go's TestDeviceWithTwoKeys.
     */
    @Test
    fun deviceWithTwoKeys() {
        val x = Group(now)
        val g = x.g
        val second = GroupCertificates.member(x.pc, SoftwareSigner().publicKeyDER, g.groupCA, x.ca, now.plusSeconds(1))
        g.record(x.pc, "pi", "member", Records.keyHashOfCert(second), x.ca, now.plusSeconds(1), caps = Records.CAPS)
        assertTrue(g.records.knows(x.pc))
        assertEquals(2, g.devices.first { it.id == x.pc }.keys.size)
        g.revoke(x.pc, x.ca, now.plusSeconds(2))
        assertEquals(listOf(g.device), g.devices.map { it.id })
    }

    @Test
    fun refused() {
        val x = Group(now)
        val set = RecordSet()
        val good = x.g.records.records.first { String(it.body).contains("\"role\":\"phone\"") }
        val forged = Member.Record(good.body, good.sig.reversedArray())
        val tampered = Member.Record(String(good.body).replace("phone", "full").toByteArray(), good.sig)
        val chained = Member.Record(good.body, good.sig, listOf(byteArrayOf(1)))
        for ((name, r) in listOf("forged" to forged, "tampered" to tampered, "chained" to chained)) assertFalse(set.add(r, x.g.groupCA), name)
        val other = PhoneGroup.create(SoftwareSigner(), SoftwareSigner().publicKeyDER, now)
        assertFalse(RecordSet().add(good, other.groupCA), "a record of another group")
        assertTrue(set.add(good, x.g.groupCA))
        assertFalse(set.add(good, x.g.groupCA), "a known record is not new")
    }

    /**
     * Runs the cases of testdata/interop/v2-records.json whose names start
     * with one of the prefixes (all of them for null) through the set: the
     * core gives each case's state, the same as Go, the Rust cbb and the
     * Swift kit. Answers how many cases ran.
     */
    private fun v2Cases(prefixes: List<String>? = null, check: ((String, RecordSet) -> Unit)? = null): Int {
        val cases = Interop.read("v2-records.json").jsonObject.getValue("cases").jsonArray.map { it.jsonObject }
        var n = 0
        for (c in cases) {
            if (c["time_unknown"]?.jsonPrimitive?.boolean == true) continue
            val name = c.str("name")
            if (prefixes != null && prefixes.none { name.startsWith(it) }) continue
            val set = RecordSet()
            set.tag = c.str("group")
            set.nowMS = c.str("now_ms").toLong()
            val records = c.getValue("records").jsonArray.map { Member.Record.fromJson(it.jsonObject) }
            val fresh = set.addAll(records, b64(c.str("group_ca")))
            if (fresh.size != records.size) continue // records the set does not keep
            set.takeClaimTimes(RecordSet.ClaimTime.list(c["first_seen"] as? JsonArray))
            val want = RecordSet.State.of(Json.parseToJsonElement(c.str("state")).jsonObject)
            assertEquals(want, set.view.state, name)
            check?.invoke(name, set)
            n++
        }
        assertTrue(n > 0, "no case of $prefixes")
        return n
    }

    @Test
    fun v2Vectors() {
        assertTrue(v2Cases() > 10)
    }

    /** The alerts say each case's stop, conflicts and claims that wait or stop the group, with the records a resolve names and the devices involved. */
    @Test
    fun alerts() {
        val kinds = mutableSetOf<GroupAlert.Kind>()
        v2Cases { name, set ->
            val st = set.view.state
            val alerts = set.alerts
            kinds += alerts.map { it.kind }
            assertEquals(st.stop == "full", alerts.any { it.kind == GroupAlert.Kind.STOPPED }, name)
            assertEquals(st.stop == "secrets", alerts.any { it.kind == GroupAlert.Kind.SECRETS_STOPPED }, name)
            for (c in st.conflicts) {
                val a = alerts.firstOrNull { a ->
                    a.kind in setOf(GroupAlert.Kind.TWO_HISTORIES, GroupAlert.Kind.ADMINS, GroupAlert.Kind.CLAIMS) &&
                        a.records.size == c.records.size && a.records.zip(c.records).all { (x, y) -> x.contentEquals(y) }
                }
                assertTrue(a != null, "$name: ${c.kind}")
                if (c.kind == "two_histories") assertTrue(a.names.isNotEmpty(), "$name: who signed two histories")
            }
            assertEquals(st.claims.count { it.state == "pending" }, alerts.count { it.kind == GroupAlert.Kind.CLAIM_PENDING }, name)
        }
        assertTrue(kinds.containsAll(listOf(GroupAlert.Kind.STOPPED, GroupAlert.Kind.TWO_HISTORIES, GroupAlert.Kind.CLAIM_PENDING)), "$kinds")
    }

    // The cases of Go's records of version 1 had these tests; each now runs
    // the cases of version 2 that took their place.

    @Test
    fun goAuthority() {
        v2Cases(listOf("basic", "record of a later version", "ignored records", "checkpoint"))
    }

    @Test
    fun goAdminPowers() {
        v2Cases(listOf("powers"))
    }

    @Test
    fun goEnvelopes() {
        v2Cases(listOf("one record under two admin CAs", "two histories", "times at the ends"))
    }

    @Test
    fun goFreeze() {
        v2Cases(listOf("freeze and thaw", "freezes crossed"))
    }

    @Test
    fun goHandover() {
        v2Cases(listOf("claim waits and takes effect", "settings delay", "claim disputed"))
    }

    @Test
    fun goHubOrder() {
        v2Cases(listOf("hubs table"))
    }

    @Test
    fun goRemovedAdmin() {
        v2Cases(listOf("root removal cuts an admin", "removed admin's device", "removed admin's claim"))
    }

    @Test
    fun goRemovedAdmins() {
        v2Cases(listOf("admin removals"))
    }

    @Test
    fun goRootMember() {
        v2Cases(listOf("removed phone after a takeover", "chain of claims"))
    }

    @Test
    fun goTakeover() {
        v2Cases(listOf("two claims", "claim after removal", "claim while another waits", "stranger's claim", "claimed root signs early"))
    }

    /**
     * A watch's records count only for its powers: removing an admin is not
     * one of them, so a revocation of an admin's key that a watch signs
     * counts for nothing, while the root's does.
     */
    @Test
    fun goWatch() {
        val x = Group(now)
        val g = x.g
        val adminKey = SoftwareSigner()
        val admin = SyncEngine.newID()
        val adminCA = GroupCertificates.adminCA(admin, adminKey.publicKeyDER, g.groupCA, x.ca)
        val adminHash = Records.keyHashOfCert(adminCA)
        g.record(admin, "B", "phone", Records.keyHash(SoftwareSigner().publicKeyDER), x.ca, now, adminHash)
        val watchKey = SoftwareSigner()
        val watch = SyncEngine.newID()
        val (watchCA, _) = g.addWatch(watch, "Watch", "wearos", watchKey.publicKeyDER, x.ca, now.plusSeconds(1))
        assertEquals(Records.WATCH_POWERS, g.devices.first { it.id == watch }.powers)
        assertFalse("remove-admins" in Records.WATCH_POWERS)
        g.records.signed(V2.revoke(listOf(adminHash), watchKey, now.plusSeconds(2)), watchKey, g.groupCA, watchCA)
        assertFalse(g.records.isRevoked(adminHash))
        assertTrue(g.devices.any { it.id == admin })
        g.records.signed(V2.revoke(listOf(adminHash), x.ca, now.plusSeconds(3)), x.ca, g.groupCA)
        assertTrue(g.records.isRevoked(adminHash))
    }

    /**
     * Writes records this kit signed for internal/group's TestSwiftRecords,
     * under the Swift kit's file name, when CBB_INTEROP_OUT names a directory.
     */
    @Test
    fun recordsForGo() {
        val dir = Interop.out ?: return
        val x = Group(now)
        val g = x.g
        g.revoke(x.pc, x.ca, now)
        val out = Wire.obj(
            "group_ca" to Wire.bytes(g.groupCA),
            "records" to JsonArray(g.records.records.map { it.toJson() }),
            "digest" to Wire.str(g.records.digest),
            "devices" to JsonArray(g.devices.map { JsonPrimitive(it.id) }),
            "revoked" to JsonArray(g.records.revoked.map { JsonPrimitive(b64(unhex(it))) }),
        )
        File(dir, "swift-records.json").writeBytes(Wire.encode(out))
    }
}
