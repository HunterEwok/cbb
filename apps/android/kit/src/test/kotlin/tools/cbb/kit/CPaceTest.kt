// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

fun unhex(s: String): ByteArray {
    val h = s.filterNot { it.isWhitespace() }
    return ByteArray(h.length / 2) { h.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}

fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

// Test vectors from draft-irtf-cfrg-cpace-21, Appendix B.1, as in
// internal/cpace/ of rsc.io/cmd/mote v0.1.3, file cpace_test.go.
class CPaceTest {
    private val prs = "Password".toByteArray()
    private val ci = "\u000bA_initiator\u000bB_responder".toByteArray()
    private val sid = unhex("7e4b4791d6a8ef019b936c79fb7f2c57")
    private val genString = unhex(
        """
        0843506163653235350850617373776f72646d000000000000000000
        00000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000180b415f696e69746961746f
        720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f
        2c57
        """,
    )
    private val gen = unhex("d04bf6d41f6a289632a2e929fa29bebd51092512a7829fdde7d314b62f05a73f")
    private val ya = unhex("21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080")
    private val ma = unhex("1d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f32")
    private val yb = unhex("848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a")
    private val mb = unhex("248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea32185623")
    private val iskIR = unhex(
        """
        6e19b875f7a561d6b3ca3dbb9ef42ac55de3e717881018204b8922b4
        d5e53bb2aa82c300bea7b65d2b671da71922ddf6472301b79bc270ad
        fa8bf413285f2263
        """,
    )

    @Test
    fun generatorString() {
        assertContentEquals(genString, CPace.generatorString(prs, ci, sid))
    }

    @Test
    fun generator() {
        assertEquals(gen.hex(), CPace.generator(prs, ci, sid).hex())
    }

    @Test
    fun vectors() {
        val a = CPace(CPace.Role.INITIATOR, prs, ci, sid, "ADa".toByteArray(), ya)
        val b = CPace(CPace.Role.RESPONDER, prs, ci, sid, "ADb".toByteArray(), yb)
        assertEquals(ma.hex(), a.message.hex())
        assertEquals(mb.hex(), b.message.hex())
        val iskA = a.finish(b.message, "ADb".toByteArray())
        val iskB = b.finish(a.message, "ADa".toByteArray())
        assertEquals(iskIR.hex(), iskA.hex())
        assertContentEquals(iskA, iskB)
        a.verify(b.confirmationTag!!)
        b.verify(a.confirmationTag!!)
        assertFailsWith<CPace.Failure> { a.finish(b.message, "ADb".toByteArray()) }
    }

    @Test
    fun wrongPassword() {
        val a = CPace(CPace.Role.INITIATOR, "123456".toByteArray(), ci, sid, ByteArray(0))
        val b = CPace(CPace.Role.RESPONDER, "123457".toByteArray(), ci, sid, ByteArray(0))
        a.finish(b.message, ByteArray(0))
        b.finish(a.message, ByteArray(0))
        assertFailsWith<CPace.Failure> { a.verify(b.confirmationTag!!) }
    }

    @Test
    fun rejectsOwnAndLowOrderMessages() {
        val a = CPace(CPace.Role.INITIATOR, prs, ci, sid, ByteArray(0))
        assertFailsWith<CPace.Failure> { a.finish(a.message, ByteArray(0)) }
        val b = CPace(CPace.Role.INITIATOR, prs, ci, sid, ByteArray(0))
        assertFailsWith<CPace.Failure> { b.finish(ByteArray(32), ByteArray(0)) }
    }

    /**
     * The scalar_mult_vfy vectors of draft-irtf-cfrg-cpace-21, Appendix
     * B.1.10, as Go's TestLowOrder and the lite member run them: u0 to u5 and
     * u7 encode low order points, non-canonical ones included, and a party
     * that receives one aborts; it takes the others.
     */
    @Test
    fun lowOrderVectors() {
        val s = unhex("af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff")
        val vectors = listOf(
            "0000000000000000000000000000000000000000000000000000000000000000" to "",
            "0100000000000000000000000000000000000000000000000000000000000000" to "",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" to "",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800" to "",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157" to "",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" to "",
            "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" to "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" to "",
            "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" to "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38",
            "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" to "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456",
            "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880" to "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a",
            "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7" to "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175",
        )
        for ((i, v) in vectors.withIndex()) {
            val (u, q) = v
            val a = CPace(CPace.Role.INITIATOR, prs, ci, sid, ByteArray(0))
            if (q.isEmpty()) {
                assertFailsWith<CPace.Failure>("u$i") { a.finish(unhex(u), ByteArray(0)) }
            } else {
                assertEquals(q, x25519(s, unhex(u)).hex(), "u$i")
                a.finish(unhex(u), ByteArray(0))
            }
        }
    }

    @Test
    fun prependLen() {
        assertContentEquals(byteArrayOf(0), CPace.prependLen(ByteArray(0)))
        assertContentEquals(byteArrayOf(0x80.toByte(), 0x01), CPace.prependLen(ByteArray(128) { 1 }).copyOf(2))
    }

    // RFC 7748, section 5.2.
    @Test
    fun x25519Vectors() {
        assertEquals(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            x25519(
                unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
            ).hex(),
        )
        assertEquals(
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            x25519(
                unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
                unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
            ).hex(),
        )
        // One iteration of the iterated test, from k = u = 9.
        val nine = ByteArray(32).also { it[0] = 9 }
        assertEquals("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", x25519(nine, nine).hex())
    }
}
