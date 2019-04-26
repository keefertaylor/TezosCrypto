// Copyright Keefer Taylor, 2019

import Base58Swift
import Foundation
import Sodium

/// A property bag representing various artifacts from signing an operation.
public struct OperationSigningResult {
  /// The original operation bytes which were signed.
  public let operationBytes: [UInt8]

  /// The hashed operation bytes which were produced via hashing and signed.
  public let hashedOperationBytes: [UInt8]

  /// The signature of the signed bytes.
  public let signature: [UInt8]

  /// The base58check encoded version of the signature, prefixed with 'edsig'
  public var base58Representation: String

  /// The operation string concatenated with a hex encoded signature.
  public let injectableHexBytes: String

  /// - Parameters:
  ///   - operationBytes: The bytes that comprised the operation.
  ///   - signature: The signature of the operation.
  public init?(operationBytes: [UInt8], hashedOperationBytes: [UInt8], signature: [UInt8]) {
    let sodium = Sodium()
    guard let edsig = Base58.encode(message: signature, prefix: Prefix.Sign.operation),
          let operationBytesHex = sodium.utils.bin2hex(operationBytes),
          let signatureHex = sodium.utils.bin2hex(signature) else {
      return nil
    }

    self.operationBytes = operationBytes
    self.hashedOperationBytes = hashedOperationBytes
    self.signature = signature
    self.injectableHexBytes = operationBytesHex + signatureHex
    self.base58Representation = edsig
  }
}

extension OperationSigningResult: CustomStringConvertible {
  public var description: String {
    return base58Representation
  }
}
