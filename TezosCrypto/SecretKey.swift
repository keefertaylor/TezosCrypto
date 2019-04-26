// Copyright Keefer Taylor, 2019

import Base58Swift
import Foundation
import MnemonicKit
import Sodium

/// Encapsulation of a secret key.
public struct SecretKey {
  /// Underlying bytes
  public let bytes: [UInt8]

  /// Base58Check representation of the key, prefixed with 'espk'.
  public var base58CheckRepresentation: String {
    // TODO: Don't force unwrap
    return Base58.encode(message: bytes, prefix: Prefix.Keys.secret)!
  }

  /// Initialize a key with the given mnemonic and passphrase.
  ///
  /// - Parameters:
  ///   - mnemonic: A mnemonic phrase to use.
  ///   - passphrase: An optional passphrase to use. Default is the empty string.
  /// - Returns: A representative secret key, or nil if an invalid mnemonic was given.
  public init?(mnemonic: String, passphrase: String = "") {
    guard let seedString = Mnemonic.deterministicSeedString(from: mnemonic, passphrase: passphrase) else {
      return nil
    }
    self.init(seedString: String(seedString[..<seedString.index(seedString.startIndex, offsetBy: 64)]))
  }

  /// Initialize a key with the given hex seed string.
  ///
  /// - Returns: A representative secret key, or nil if the seed string was in an unexpected format.
  public init?(seedString: String) {
    let sodium = Sodium()
    guard let seed = sodium.utils.hex2bin(seedString),
          let keyPair = sodium.sign.keyPair(seed: seed) else {
            return nil
    }
    self.init(keyPair.secretKey)
  }

  /// Initialize a secret key with the given base58check encoded string.
  ///
  /// The string must begin with 'edsk'.
  public init?(_ string: String) {
    guard let bytes = Base58.base58CheckDecodeWithPrefix(string: string, prefix: Prefix.Keys.secret) else {
      return nil
    }
    self.init(bytes)
  }

  /// Initialize a key with the given bytes.
  public init(_ bytes: [UInt8]) {
    self.bytes = bytes
  }
}

extension SecretKey: CustomStringConvertible {
  public var description: String {
    return base58CheckRepresentation
  }
}

extension SecretKey: Equatable {
  public static func == (lhs: SecretKey, rhs: SecretKey) -> Bool {
    return lhs.base58CheckRepresentation == rhs.base58CheckRepresentation
  }
}
