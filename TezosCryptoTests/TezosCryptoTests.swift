// Copyright Keefer Taylor, 2019

import TezosCrypto
import XCTest

class TezosCryptoTests: XCTestCase {
  private let mnemonic =
    "soccer click number muscle police corn couch bitter gorilla camp camera shove expire praise pill"
  private let passphrase = "TezosKitTest"

  // Expected outputs for a wallet without a passphrase.
  let expectedPublicKeyNoPassphrase = "edpku9ZF6UUAEo1AL3NWy1oxHLL6AfQcGYwA5hFKrEKVHMT3Xx889A"
  let expectedSecretKeyNoPassphrase =
    "edskS4pbuA7rwMjsZGmHU18aMP96VmjegxBzwMZs3DrcXHcMV7VyfQLkD5pqEE84wAMHzi8oVZF6wbgxv3FKzg7cLqzURjaXUp"
  let expectedPublicKeyHashNoPassphrase = "tz1Y3qqTg9HdrzZGbEjiCPmwuZ7fWVxpPtRw"

  public func testValidateAddress() {
    let validAddress = "tz1PnyUZjRTFdYbYcJFenMwZanXtVP17scPH"
    let validOriginatedAddress = "KT1Agon3ARPS7U74UedWpR96j1CCbPCsSTsL"
    let invalidAddress = "tz1PnyUZjRTFdYbYcJFenMwZanXtVP17scPh"
    let publicKey = "edpkvESBNf3cbx7sb4CjyurMxFJjCkUVkunDMjsXD4Squoo5nJR4L4"
    let nonBase58Address = "tz10ol1OLscph"

    XCTAssertTrue(TezosCryptoUtils.validateAddress(address: validAddress))
    XCTAssertFalse(TezosCryptoUtils.validateAddress(address: validOriginatedAddress))
    XCTAssertFalse(TezosCryptoUtils.validateAddress(address: invalidAddress))
    XCTAssertFalse(TezosCryptoUtils.validateAddress(address: publicKey))
    XCTAssertFalse(TezosCryptoUtils.validateAddress(address: nonBase58Address))
  }

//  public func testVerifyBytes() {
//    let fakeOperation = "123456"
//    guard let keyPair1 = TezosCryptoUtils.keyPair(from: "cce78b57ed8f4ec6767ed35f3aa41df525a03455e24bcc45a8518f63fbeda772"),
//      let keyPair2 = TezosCryptoUtils.keyPair(from: "cc90fecd0a596e2cd41798612682395faa2ebfe18945a88c6f01e4bfab17c3e3"),
//      let tezosPublicKey1 = TezosCryptoUtils.tezosPublicKey(from: keyPair1.public),
//      let tezosSecretKey1 = TezosCryptoUtils.tezosSecretKey(from: keyPair1.secret.bytes),
//      let tezosPublicKey2 = TezosCryptoUtils.tezosSecretKey(from: keyPair2.secret.bytes) else {
//        XCTFail()
//        return
//    }
//
//    guard let result = TezosCrypto.signForgedOperation(operation: fakeOperation, secretKey: tezosSecretKey1) else {
//        XCTFail()
//        return
//    }
//
//    XCTAssertTrue(
//      TezosCrypto.verifyBytes(bytes: result.operationBytes, signature: result.signature, publicKey: tezosPublicKey1)
//    )
//    XCTAssertFalse(
//      TezosCrypto.verifyBytes(
//        bytes: result.operationBytes,
//        signature: result.signature,
//        publicKey: tezosPublicKey2
//      )
//    )
//    XCTAssertFalse(
//      TezosCrypto.verifyBytes(bytes: result.operationBytes, signature: [1, 2, 3], publicKey: tezosPublicKey1)
//    )
//  }
//
//  public func testSignForgedOperation() {
//    let operation = "deadbeef"
//    guard let result = TezosCrypto.signForgedOperation(
//      operation: operation,
//      secretKey: expectedSecretKeyNoPassphrase
//    ) else {
//      XCTFail()
//      return
//    }
//
//    XCTAssertEqual(
//      result.signature,
//      [
//        208, 47, 19, 208, 168, 253, 44, 130, 231, 240, 15, 213, 223, 59, 178, 60, 130, 146, 175, 120, 119, 21, 237, 130,
//        115, 88, 31, 213, 202, 126, 150, 205, 13, 237, 56, 251, 254, 240, 202, 228, 141, 180, 235, 175, 184, 189, 172,
//        121, 43, 25, 235, 97, 235, 140, 144, 168, 32, 75, 190, 101, 126, 99, 117, 13
//      ]
//    )
//
//    // swiftlint:disable line_length
//    XCTAssertEqual(
//      result.injectableHexBytes,
//      "deadbeefd02f13d0a8fd2c82e7f00fd5df3bb23c8292af787715ed8273581fd5ca7e96cd0ded38fbfef0cae48db4ebafb8bdac792b19eb61eb8c90a8204bbe657e63750d"
//    )
//    // swiftlint:enable line_length
//
//    XCTAssertEqual(
//      result.base58Representation,
//      "edsigu13UN5tAjQsxaLmXL7vCXM9BRggVDygne5LDZs7fHNH61PXfgbmXaAAq63GR8gqgeqa3aYNH4dnv18LdHaSCetC9sSJUCF"
//    )
//  }
}
