// Copyright Keefer Taylor, 2019

import Foundation
import TezosCrypto
import XCTest

final class SecretKeyTests: XCTestCase {
  func testBase58CheckRepresentation() {
    guard let secretKey = SecretKey(mnemonic: .mnemonic) else {
      XCTFail()
      return
    }

    XCTAssertEqual(
      secretKey.base58CheckRepresentation,
      "edskS4pbuA7rwMjsZGmHU18aMP96VmjegxBzwMZs3DrcXHcMV7VyfQLkD5pqEE84wAMHzi8oVZF6wbgxv3FKzg7cLqzURjaXUp"
    )
  }

  func testInitFromBase58CheckRepresntation_ValidString() {
    let secretKeyFromString =
      SecretKey("edskS4pbuA7rwMjsZGmHU18aMP96VmjegxBzwMZs3DrcXHcMV7VyfQLkD5pqEE84wAMHzi8oVZF6wbgxv3FKzg7cLqzURjaXUp")
    XCTAssertNotNil(secretKeyFromString)

    guard let secretKeyFromMnemonic = SecretKey(mnemonic: .mnemonic) else {
      XCTFail()
      return
    }

    XCTAssertEqual(secretKeyFromString, secretKeyFromMnemonic)
  }

  func testInitFromBase58CheckRepresntation_InvalidBase58() {
    XCTAssertNil(
      SecretKey("edsko0O")
    )
  }

  // TODO: Test invalid mnemonic
  // TODO: Test invalid hex seed string
}

// TODO: Refactor generally.
extension String {
  public static let mnemonic =
    "soccer click number muscle police corn couch bitter gorilla camp camera shove expire praise pill"
}
