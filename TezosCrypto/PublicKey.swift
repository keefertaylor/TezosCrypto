// Copyright Keefer Taylor, 2019.

import Base58Swift
import Foundation
import Sodium

/// Encapsulation of a Public Key.
public struct PublicKey {
  /// Underlying bytes.
  public let bytes: [UInt8]

  /// Curve type.
  public let signingCurve: EllipticalCurve

  /// Base58Check representation of the key, prefixed with 'edpk'.
  public var base58CheckRepresentation: String {
    return Base58.encode(message: bytes, prefix: Prefix.Keys.public)!
  }

  /// Public key hash representation of the key.
  public var publicKeyHash: String {
    // TODO: Use a sodium singleton
    let sodium = Sodium()
    guard let hash = sodium.genericHash.hash(message: bytes, key: [], outputLength: 20) else {
      return ""
    }
    return Base58.encode(message: hash, prefix: Prefix.Address.tz1)!
  }

  /// Initialize a key with the given bytes and signing curve.
  public init(bytes: [UInt8], signingCurve: EllipticalCurve) {
    self.bytes = bytes
    self.signingCurve = signingCurve
  }

  /// Initialize a public key with the given base58check encoded string.
  ///
  /// The string must begin with 'edpk'.
  public init?(string: String, signingCurve: EllipticalCurve) {
    guard let bytes = Base58.base58CheckDecodeWithPrefix(string: string, prefix: Prefix.Keys.public) else {
      return nil
    }
    self.init(bytes: bytes, signingCurve: signingCurve)
  }

  /// Initialize a key from the given secret key with the given signing curve.
  public init(secretKey: SecretKey, signingCurve: EllipticalCurve) {
    self.bytes = Array(secretKey.bytes[32...])
    self.signingCurve = signingCurve
  }
}

extension PublicKey: CustomStringConvertible {
  public var description: String {
    return base58CheckRepresentation
  }
}

extension PublicKey: Equatable {
  public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
    return lhs.base58CheckRepresentation == rhs.base58CheckRepresentation
  }
}
