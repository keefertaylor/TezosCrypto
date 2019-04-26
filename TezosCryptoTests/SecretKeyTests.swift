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

  func testInvalidMnemonic() {
    let invalidMnemonic =
      "TezosKit TezosKit TezosKit TezosKit TezosKit TezosKit TezosKit TezosKit TezosKit TezosKit TezosKit"
    XCTAssertNil(SecretKey(mnemonic: invalidMnemonic))
  }

  func testInvalidSeedString() {
    let invalidSeedString = "abcdefghijklmnopqrstuvwxyz"
    XCTAssertNil(SecretKey(seedString: invalidSeedString))
  }
}

