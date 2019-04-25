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

  // TODO: Test invalid mnemonic
  // TODO: Test invalid hex seed string
}

// TODO: Refactor generally.
extension String {
  public static let mnemonic =
    "soccer click number muscle police corn couch bitter gorilla camp camera shove expire praise pill"
}
