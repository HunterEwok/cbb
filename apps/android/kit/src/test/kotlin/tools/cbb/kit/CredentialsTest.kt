// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CredentialsTest {
    private fun hashes(l: List<ByteArray>) = l.map { b64(it) }

    /** testdata/interop/v2-credentials.json, from Go's TestGoCredentialVectors. */
    @Test
    fun goCredentials() {
        val v = Interop.read("v2-credentials.json").jsonObject
        val ca = b64(v.str("group_ca"))
        val s = RecordSet()
        s.addAll(v.getValue("records").jsonArray.map { Member.Record.fromJson(it.jsonObject) }, ca)
        val l = ServerCredentials.lists(s)
        val want = v.getValue("lists").jsonObject
        assertEquals(want.getValue("Hubs").jsonArray.map { it.jsonPrimitive.content }, hashes(l.hubs))
        assertEquals(want.getValue("Admins").jsonArray.map { it.jsonPrimitive.content }, hashes(l.admins))
        assertEquals(want.getValue("Members").jsonArray.map { it.jsonPrimitive.content }, hashes(l.members))

        val cred = { k: String -> ServerCredentials.Credential.fromJson(v.getValue(k).jsonObject) }
        val period = cred("period")
        val hubs = cred("hubs")
        val members = cred("members")
        val servers = v.getValue("servers").jsonArray.map { ServerCredentials.Credential.fromJson(it.jsonObject) }
        val root = CertificateInfo(ca).publicKey
        val isMember = { k: ByteArray -> s.devices.any { d -> d.keys.any { it.contentEquals(k) } } }

        val store = CredentialStore(ca)
        val (fresh, errs) = store.add(root, isMember, listOf(period, hubs, members) + servers)
        assertEquals(emptyList(), errs)
        assertEquals(3 + servers.size, fresh.size)
        val (_, hb) = assertNotNull(store.hubs())
        assertEquals(v.str("pseudonym"), ServerCredentials.pseudonym(hb.hubs[0]))
        assertEquals(hashes(store.serverKeys(l.hubs)), hashes(hb.hubs.take(l.hubs.size)))
        assertFalse(store.listStale(hb.hubs, store.serverKeys(l.hubs), true))
        assertFalse(store.listStale(hb.admins, store.serverKeys(l.admins), false))
        // Again: nothing new.
        assertEquals(0, store.add(root, isMember, listOf(period, hubs)).first.size)

        val now = v.getValue("now_ms").jsonPrimitive.long
        val p = ServerCredentials.checkPresented(listOf(hubs, members, period), now)
        assertNotNull(p.members)
        assertNotNull(p.period)
        for (b in v.getValue("bad").jsonArray.map { it.jsonObject }) {
            val set = b.getValue("set").jsonArray.map { ServerCredentials.Credential.fromJson(it.jsonObject) }
            assertFailsWith<ServerCredentials.Refused>(b.str("name")) { ServerCredentials.checkPresented(set, now) }
        }
        val forged = ServerCredentials.Credential(hubs.body.copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() }, hubs.sig, hubs.key)
        assertFailsWith<ServerCredentials.Refused> { forged.open() }
        // Encoding again gives Go's JSON.
        assertEquals(v.getValue("hubs").jsonObject, hubs.toJson())
    }

    /** Credentials the kit signs, as a root phone does for its period, are what the store and a server take. */
    @Test
    fun signed() {
        val rootKey = SoftwareSigner()
        val ca = GroupCertificates.groupCA(rootKey, java.time.Instant.ofEpochMilli(1_790_000_000_000))
        val tag = GroupCertificates.tag(ca)
        val now = 1_792_000_000_000L
        val periodKey = SoftwareSigner()
        val member = SoftwareSigner()
        val server = SoftwareSigner()
        val periodTag = ServerCredentials.newPeriodTag()
        val period = ServerCredentials.signPeriod(tag, periodTag, periodKey.publicKeyDER, 1, now, rootKey)
        val p = period.open()
        val srv = ServerCredentials.signServer(p, server.publicKeyDER, 1, member)
        val serverHash = sha256(server.publicKeyDER)
        val hubs = ServerCredentials.signHubs(p, listOf(serverHash), emptyList(), 2, periodKey)
        val members = ServerCredentials.signMembers(p, listOf(serverHash), 3, periodKey)
        assertEquals(4, hubs.open().hubs.size)
        assertEquals(4, hubs.open().admins.size)

        val store = CredentialStore(ca)
        val memberHash = sha256(member.publicKeyDER)
        val (fresh, errs) = store.add(rootKey.publicKeyDER, { it.contentEquals(memberHash) }, listOf(members, hubs, srv, period))
        assertEquals(emptyList(), errs)
        assertEquals(4, fresh.size)
        assertContentEquals(serverHash, store.server(memberHash))
        assertContentEquals(memberHash, store.memberOfServer(serverHash))
        assertFalse(store.periodStale(rootKey.publicKeyDER, { it.contentEquals(memberHash) }, now + 1000))
        assertTrue(store.periodStale(rootKey.publicKeyDER, { it.contentEquals(memberHash) }, now + ServerCredentials.PERIOD_RENEW_MS))
        // A removal: the member that signed a server key is gone.
        assertTrue(store.periodStale(rootKey.publicKeyDER, { false }, now + 1000))
        assertTrue(ServerCredentials.checkPresented(listOf(hubs, members), now + 1000).members != null)

        // A period another key signed is not the group's.
        val stranger = ServerCredentials.signPeriod(tag, ServerCredentials.newPeriodTag(), periodKey.publicKeyDER, 9, now, SoftwareSigner())
        assertEquals(1, store.add(rootKey.publicKeyDER, { true }, listOf(stranger)).second.size)
        // A newer period with another tag drops the rest.
        val next = ServerCredentials.signPeriod(tag, ServerCredentials.newPeriodTag(), periodKey.publicKeyDER, 5, now, rootKey)
        assertEquals(1, store.add(rootKey.publicKeyDER, { true }, listOf(next)).first.size)
        assertNull(store.hubs())
        assertNull(store.server(memberHash))
        assertEquals(1, store.all.size)

        // It keeps what it saved.
        val back = CredentialStore.fromJson(store.toJson(), ca, rootKey.publicKeyDER) { true }
        assertEquals(store.all, back.all)
        assertEquals(ServerCredentials.nextVersion(5, now), now / 1000)
    }

    /** Keys in memory, as the app keeps them in the Keystore. */
    private class Keys : PeriodKeys {
        val keys = mutableMapOf<String, SoftwareSigner>()
        override fun get(kind: String, tag: String) = keys.getOrPut("$kind $tag") { SoftwareSigner() }
        override fun has(kind: String, tag: String) = "$kind $tag" in keys
        override fun keep(tag: String) {
            keys.keys.retainAll { it.endsWith(" $tag") }
        }
    }

    /** A root phone starts a period, signs its own server key and the lists, and asks for the root key only for the period. */
    @Test
    fun rootStartsAPeriod() {
        val t0 = java.time.Instant.ofEpochMilli(1_792_000_000_000)
        val rootKey = SoftwareSigner()
        val member = SoftwareSigner()
        val g = PhoneGroup.create(rootKey, member.publicKeyDER, t0, "Root")
        val store = CredentialStore(g.groupCA)
        val keys = Keys()
        var asked = 0
        val root = { asked++; rootKey }
        val now = t0.toEpochMilli()
        val signed = CredentialRefresh.refresh(store, g.records, g.groupCA, g.currentRoot, member, keys, now, root)
        assertEquals(listOf("period", "server", "hubs", "members"), signed.map { it.open().type })
        assertEquals(1, asked)
        val mine = sha256(keys.get(PeriodKeys.SERVER_KEY, store.period(rootKey.publicKeyDER)!!.second.tag).publicKeyDER)
        assertTrue(store.members()!!.second.members.any { it.contentEquals(mine) })
        // What it registers with at a relay.
        val reg = assertNotNull(store.registration(g.records, rootKey.publicKeyDER, mine))
        assertEquals(listOf("hubs", "members", "period"), reg.credentials.map { it.open().type })
        assertEquals(listOf(b64(g.groupCA)), reg.roots.map { b64(it) })
        assertEquals(mapOf(ServerCredentials.pseudonym(mine) to g.records.devices.single().id), reg.names)
        assertNotNull(ServerCredentials.checkPresented(reg.credentials, now).period)
        assertNull(store.registration(g.records, rootKey.publicKeyDER, sha256(SoftwareSigner().publicKeyDER)))
        // Nothing changed: nothing to sign, no Face ID.
        assertEquals(0, CredentialRefresh.refresh(store, g.records, g.groupCA, g.currentRoot, member, keys, now + 1000, root).size)
        assertEquals(1, asked)
        // A month on: a new period, and the keys of the one before are gone.
        val later = CredentialRefresh.refresh(store, g.records, g.groupCA, g.currentRoot, member, keys, now + ServerCredentials.PERIOD_RENEW_MS, root)
        assertEquals("period", later.first().open().type)
        assertEquals(2, asked)
        assertEquals(2, keys.keys.size)
        // A root whose key cannot sign now keeps the period, and still signs the lists.
        val waiting = CredentialRefresh.refresh(store, g.records, g.groupCA, g.currentRoot, member, keys, now + 2 * ServerCredentials.PERIOD_RENEW_MS) { null }
        assertTrue(waiting.none { it.open().type == "period" })
        // Without the root key, and with a server key of its own, it signs only that.
        val other = CredentialStore(g.groupCA)
        other.add(rootKey.publicKeyDER, { true }, store.all)
        val alone = CredentialRefresh.refresh(other, g.records, g.groupCA, g.currentRoot, member, Keys(), now + ServerCredentials.PERIOD_RENEW_MS + 1000)
        assertEquals(listOf("server"), alone.map { it.open().type })
    }
}
