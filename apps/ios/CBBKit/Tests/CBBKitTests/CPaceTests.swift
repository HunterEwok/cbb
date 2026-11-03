// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import XCTest

func unhex(_ s: String) -> [UInt8] {
    let h = s.filter { !$0.isWhitespace }
    var out: [UInt8] = []
    var i = h.startIndex
    while i < h.endIndex {
        let j = h.index(i, offsetBy: 2)
        out.append(UInt8(h[i..<j], radix: 16)!)
        i = j
    }
    return out
}

func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

// Test vectors from draft-irtf-cfrg-cpace-21, Appendix B.1, as in
// internal/third_party/cpace/cpace_test.go.
final class CPaceTests: XCTestCase {
    let prs = Array("Password".utf8)
    let ci = Array("\u{0b}A_initiator\u{0b}B_responder".utf8)
    let sid = unhex("7e4b4791d6a8ef019b936c79fb7f2c57")
    let genString = unhex("""
        0843506163653235350850617373776f72646d000000000000000000
        00000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000180b415f696e69746961746f
        720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f
        2c57
        """)
    let gen = unhex("d04bf6d41f6a289632a2e929fa29bebd51092512a7829fdde7d314b62f05a73f")
    let ya = unhex("21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080")
    let ma = unhex("1d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f32")
    let yb = unhex("848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a")
    let mb = unhex("248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea32185623")
    let iskIR = unhex("""
        6e19b875f7a561d6b3ca3dbb9ef42ac55de3e717881018204b8922b4
        d5e53bb2aa82c300bea7b65d2b671da71922ddf6472301b79bc270ad
        fa8bf413285f2263
        """)

    func testGeneratorString() {
        XCTAssertEqual(CPace.generatorString(password: prs, channelID: ci, sessionID: sid), genString)
    }

    func testGenerator() {
        XCTAssertEqual(hex(CPace.generator(password: prs, channelID: ci, sessionID: sid)), hex(gen))
    }

    func testVectors() throws {
        var a = try CPace(role: .initiator, password: prs, channelID: ci, sessionID: sid, ad: Array("ADa".utf8), scalar: ya)
        var b = try CPace(role: .responder, password: prs, channelID: ci, sessionID: sid, ad: Array("ADb".utf8), scalar: yb)
        XCTAssertEqual(hex(a.message), hex(ma))
        XCTAssertEqual(hex(b.message), hex(mb))
        let iskA = try a.finish(peerMessage: b.message, peerAD: Array("ADb".utf8))
        let iskB = try b.finish(peerMessage: a.message, peerAD: Array("ADa".utf8))
        XCTAssertEqual(hex(iskA), hex(iskIR))
        XCTAssertEqual(iskA, iskB)
        try a.verify(peerTag: b.confirmationTag!)
        try b.verify(peerTag: a.confirmationTag!)
        XCTAssertThrowsError(try a.finish(peerMessage: b.message, peerAD: Array("ADb".utf8)))
    }

    func testWrongPassword() throws {
        var a = try CPace(role: .initiator, password: Array("123456".utf8), channelID: ci, sessionID: sid, ad: [])
        var b = try CPace(role: .responder, password: Array("123457".utf8), channelID: ci, sessionID: sid, ad: [])
        _ = try a.finish(peerMessage: b.message, peerAD: [])
        _ = try b.finish(peerMessage: a.message, peerAD: [])
        XCTAssertThrowsError(try a.verify(peerTag: b.confirmationTag!))
    }

    func testRejectsOwnAndLowOrderMessages() throws {
        var a = try CPace(role: .initiator, password: prs, channelID: ci, sessionID: sid, ad: [])
        XCTAssertThrowsError(try a.finish(peerMessage: a.message, peerAD: []))
        var b = try CPace(role: .initiator, password: prs, channelID: ci, sessionID: sid, ad: [])
        XCTAssertThrowsError(try b.finish(peerMessage: [UInt8](repeating: 0, count: 32), peerAD: []))
    }

    /// The scalar_mult_vfy vectors of draft-irtf-cfrg-cpace-21, Appendix
    /// B.1.10, as Go's TestLowOrder and the lite member run them: u0 to u5
    /// and u7 encode low order points, non-canonical ones included, and a
    /// party that receives one aborts; it takes the others.
    func testLowOrderVectors() throws {
        let vectors: [(String, String)] = [
        ("0000000000000000000000000000000000000000000000000000000000000000", ""),
        ("0100000000000000000000000000000000000000000000000000000000000000", ""),
        ("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ""),
        ("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", ""),
        ("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", ""),
        ("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ""),
        ("daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806"),
        ("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ""),
        ("dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38"),
        ("d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456"),
        ("cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880", "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a"),
        ("4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7", "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175"),
        ]
        for (i, (u, q)) in vectors.enumerated() {
            var a = try CPace(role: .initiator, password: prs, channelID: ci, sessionID: sid, ad: [])
            if q.isEmpty {
                XCTAssertThrowsError(try a.finish(peerMessage: unhex(u), peerAD: []), "u\(i)")
            } else {
                XCTAssertNoThrow(try a.finish(peerMessage: unhex(u), peerAD: []), "u\(i)")
            }
        }
    }

    func testPrependLen() {
        XCTAssertEqual(CPace.prependLen([]), [0])
        XCTAssertEqual(CPace.prependLen([UInt8](repeating: 1, count: 128)).prefix(2), [0x80, 0x01])
    }
}
