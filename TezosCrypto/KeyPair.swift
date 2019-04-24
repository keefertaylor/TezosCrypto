// Copyright Keefer Taylor, 2019

import Foundation
import Sodium

/// Generic KeyPair protocol containing private and public keys.
public protocol KeyPair {
  var `public`: [UInt8] { get }
  var secret: SecretKey { get }
}

/// Extension on Sodium's Sign.KeyPair to work with TezosKit code.
extension Sign.KeyPair: KeyPair {
  public var secret: SecretKey {
    return TezosCrypto.SecretKey(secretKey)
  }

  public var `public`: [UInt8] {
    return publicKey
  }
}
