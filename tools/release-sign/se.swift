// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The release key in the Mac's Secure Enclave, for release-sign's se:KEY
// signer. KEY is a file that holds the key's handle (its
// dataRepresentation: the key itself never leaves the Secure Enclave, and
// the handle works only on this Mac). Each signature asks for Touch ID.
//
//	swift tools/release-sign/se.swift create KEY   (makes the key, prints its public key)
//	swift tools/release-sign/se.swift public KEY   (prints the public key, PEM)
//	swift tools/release-sign/se.swift sign KEY     (signs stdin, writes a DER signature to stdout)

import CryptoKit
import Foundation
import LocalAuthentication

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("se.swift: \(message)\n".utf8))
    exit(1)
}

func load(_ path: String, context: LAContext? = nil) -> SecureEnclave.P256.Signing.PrivateKey {
    guard let data = FileManager.default.contents(atPath: path) else { fail("cannot read \(path)") }
    do {
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data, authenticationContext: context)
    } catch {
        fail("\(path) is not a key of this Mac's Secure Enclave: \(error)")
    }
}

let args = CommandLine.arguments
guard args.count == 3 else { fail("usage: se.swift create|public|sign KEY") }
let path = args[2]
switch args[1] {
case "create":
    guard SecureEnclave.isAvailable else { fail("this Mac has no Secure Enclave") }
    guard !FileManager.default.fileExists(atPath: path) else { fail("\(path) exists; not replacing a key") }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       [.privateKeyUsage, .biometryCurrentSet], &error) else {
        fail("no access control: \(String(describing: error))")
    }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        FileManager.default.createFile(atPath: path, contents: key.dataRepresentation, attributes: [.posixPermissions: 0o600])
        print(key.publicKey.pemRepresentation)
    } catch {
        fail("cannot make the key: \(error)")
    }
case "public":
    print(load(path).publicKey.pemRepresentation)
case "sign":
    let data = FileHandle.standardInput.readDataToEndOfFile()
    let context = LAContext()
    context.localizedReason = "sign a cbb release"
    do {
        let sig = try load(path, context: context).signature(for: data)
        FileHandle.standardOutput.write(sig.derRepresentation)
    } catch {
        fail("signing failed: \(error)")
    }
default:
    fail("usage: se.swift create|public|sign KEY")
}
