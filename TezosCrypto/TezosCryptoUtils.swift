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
    guard let decodedPublicKeyBytes = self.decodedKey(from: publicKey, prefix: Prefix.Keys.public) else {
      return false
    }
    return sodium.sign.verify(message: bytes, publicKey: decodedPublicKeyBytes, signature: signature)
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
    guard let decodedSecretKeyBytes = self.decodedKey(from: secretKey, prefix: Prefix.Keys.secret),
          let operationBytes = sodium.utils.hex2bin(operation) else {
      return nil
    }
    let watermarkedOperation = Prefix.Watermark.operation + operationBytes

    guard  let hashedOperation = sodium.genericHash.hash(message: watermarkedOperation, outputLength: 32),
      let signature = sodium.sign.signature(message: hashedOperation, secretKey: decodedSecretKeyBytes) else {
        return nil
    }

    return OperationSigningResult(operationBytes: operationBytes, signature: signature)
  }

  /// Encode a Base58 String from the given message and prefix.
  ///
  /// The returned address is a Base58 encoded String with the following format: [prefix][key][4 byte checksum]
  public static func encode(message: [UInt8], prefix: [UInt8]) -> String? {
    let prefixedMessage = prefix + message
    return Base58.base58CheckEncode(prefixedMessage)
  }

  /// Decode an original key from the Base58 encoded key containing a prefix and checksum.
  private static func decodedKey(from encodedKey: String, prefix: [UInt8]) -> [UInt8]? {
    guard var decodedBytes = Base58.base58CheckDecode(encodedKey) else {
      return nil
    }

    // Decoded key will have extra bytes at the beginning for the prefix. Drop these bytes in order to get the original
    // key.
    decodedBytes.removeSubrange(0 ..< prefix.count)
    return decodedBytes
  }

  /// Extract a bytes for a public key from a given base58check encoded secret key prefixed with "edsk".
  public static func extractPublicKeyBytes(secretKey: String) -> [UInt8]? {
    guard let decodedSecretKeyBytes = self.decodedKey(from: secretKey, prefix: Prefix.Keys.secret) else {
      return nil
    }
    return Array(decodedSecretKeyBytes[32...])
  }
}
