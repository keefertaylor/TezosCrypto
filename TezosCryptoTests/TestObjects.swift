// Copyright Keefer Taylor, 2019

import Foundation

/// Common objects used in tests.

extension String {
  /// Mnemonic used in tests to generate a secret key.
  public static let mnemonic =
    "soccer click number muscle police corn couch bitter gorilla camp camera shove expire praise pill"

  /// Base58Check encoded secret key generated from the test mnemonic.
  public static let expectedSecretKey =
    "edskS4pbuA7rwMjsZGmHU18aMP96VmjegxBzwMZs3DrcXHcMV7VyfQLkD5pqEE84wAMHzi8oVZF6wbgxv3FKzg7cLqzURjaXUp"
}
