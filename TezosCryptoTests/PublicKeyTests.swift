// Copyright Keefer Taylor, 2019

import Foundation
import TezosCrypto
import XCTest

final class PublicKeyTests: XCTestCase {
  func testBase58CheckRepresentation() {
    guard let secretKey = SecretKey(mnemonic: .mnemonic) else {
      XCTFail()
      return
    }
    let publicKey = PublicKey(secretKey: secretKey, signingCurve: .ed25519)

    XCTAssertEqual(
      publicKey.base58CheckRepresentation,
      "edpku9ZF6UUAEo1AL3NWy1oxHLL6AfQcGYwA5hFKrEKVHMT3Xx889A"
    )
  }

  func testPublicKeyHash() {
    guard let secretKey = SecretKey(mnemonic: .mnemonic) else {
      XCTFail()
      return
    }
    let publicKey = PublicKey(secretKey: secretKey, signingCurve: .ed25519)

    XCTAssertEqual(
      publicKey.publicKeyHash,
      "tz1Y3qqTg9HdrzZGbEjiCPmwuZ7fWVxpPtRw"
    )
  }

  func testInitFromBase58CheckRepresentation_ValidString() {
    let publicKeyFromString =
      PublicKey(string: "edpku9ZF6UUAEo1AL3NWy1oxHLL6AfQcGYwA5hFKrEKVHMT3Xx889A", signingCurve: .ed25519)
    XCTAssertNotNil(publicKeyFromString)

    guard let secretKey = SecretKey(mnemonic: .mnemonic) else {
      XCTFail()
      return
    }
    let publicKeyFromSecretKey = PublicKey(secretKey: secretKey, signingCurve: .ed25519)

    XCTAssertEqual(publicKeyFromString, publicKeyFromSecretKey)
  }

  func testInitFromBase58CheckRepresentation_InvalidBase58() {
    XCTAssertNil(
      PublicKey(string: "edsko0O", signingCurve: .ed25519)
    )
  }
}
