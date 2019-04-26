// Copyright Keefer Taylor, 2019

import Base58Swift
import CommonCrypto
import CryptoSwift
import Foundation
import Sodium

/// A static helper class that provides utility functions for cyptography.
public enum TezosCryptoUtils {
  private static let sodium: Sodium = Sodium()

  /// Check that a given address is valid public key hash address.
  public static func validateAddress(address: String) -> Bool {
    // Decode bytes. This call verifies the checksum is correct.
    guard let decodedBytes = Base58.base58CheckDecode(address) else {
      return false
    }

    // Check that the prefix is correct.
    for (i, byte) in Prefix.Address.tz1.enumerated() where decodedBytes[i] != byte {
      return false
    }

    return true
  }

  /// Verify that the given signature is a signed version of the given bytes by the secret key associated with the given
  /// public key.
  public static func verifyBytes(bytes: [UInt8], signature: [UInt8], publicKey: String) -> Bool {
    guard let publicKey = PublicKey(string: publicKey, signingCurve: .ed25519) else {
      return false
    }
    return sodium.sign.verify(message: bytes, publicKey: publicKey.bytes, signature: signature)
  }

  /// Sign a forged operation with the given secret key.
  ///
  /// - Parameters:
  ///   - operation A hex encoded string representing the forged operation
  ///   - secretKey A base58check encoded secret key prefixed with 'edsk' which will sign the operation.
  /// - Returns: A OperationSigningResult with the results of the signing if successful, otherwise nil.
  public static func signForgedOperation(
    operation: String,
    secretKey: String
  ) -> OperationSigningResult? {
    guard let secretKey = SecretKey(secretKey),
          let operationBytes = sodium.utils.hex2bin(operation) else {
      return nil
    }
    let watermarkedOperation = Prefix.Watermark.operation + operationBytes

    guard let hashedOperationBytes = sodium.genericHash.hash(message: watermarkedOperation, outputLength: 32),
          let signature = sodium.sign.signature(message: hashedOperationBytes, secretKey: secretKey.bytes) else {
        return nil
    }

    return OperationSigningResult(
      operationBytes: operationBytes,
      hashedOperationBytes: hashedOperationBytes,
      signature: signature
    )
  }

  /// Encode a Base58 String from the given message and prefix.
  ///
  /// The returned address is a Base58 encoded String with the following format: [prefix][key][4 byte checksum]
  public static func encode(message: [UInt8], prefix: [UInt8]) -> String? {
    let prefixedMessage = prefix + message
    return Base58.base58CheckEncode(prefixedMessage)
  }
}
