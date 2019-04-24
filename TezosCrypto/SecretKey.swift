// Copyright Keefer Taylor, 2019

import Foundation

/// Encapsulation of a secret key.
public struct SecretKey {
  public let bytes: [UInt8]

  public init(_ bytes: [UInt8]) {
    self.bytes = bytes
  }
}
