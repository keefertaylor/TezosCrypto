// Copyright Keefer Taylor, 2019

import Base58Swift
import CommonCrypto
import CryptoSwift
import Foundation
import Sodium

/// A static helper class that provides utility functions for cyptography.
public enum TezosCryptoUtils {
  /// Check that a given address is valid public key hash.
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

  /// Verify that the given signature matches the given input bytes.
  ///
  /// - Parameters:
  ///   - bytes: The bytes to check.
  ///   - signature: The proposed signature of the bytes.
  ///   - publicKey: The proposed public key.
  /// - Returns: True if the public key and signature match the given bytes.
  public static func verifyBytes(bytes: [UInt8], signature: [UInt8], publicKey: PublicKey) -> Bool {
    switch publicKey.signingCurve {
    case .ed25519:
      return Sodium.shared.sign.verify(message: bytes, publicKey: publicKey.bytes, signature: signature)
    }
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
          let operationBytes = Sodium.shared.utils.hex2bin(operation) else {
      return nil
    }
    let watermarkedOperation = Prefix.Watermark.operation + operationBytes

    guard let hashedOperationBytes = Sodium.shared.genericHash.hash(message: watermarkedOperation, outputLength: 32),
          let signature = Sodium.shared.sign.signature(message: hashedOperationBytes, secretKey: secretKey.bytes) else {
        return nil
    }

    return OperationSigningResult(
      operationBytes: operationBytes,
      hashedOperationBytes: hashedOperationBytes,
      signature: signature
    )
  }
}
