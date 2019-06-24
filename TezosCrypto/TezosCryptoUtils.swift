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

  /// Verify that the given signature matches the given input hex.
  ///
  /// - Parameters:
  ///   - hex: The hex to check.
  ///   - signature: The proposed signature of the bytes.
  ///   - publicKey: The proposed public key.
  /// - Returns: True if the public key and signature match the given bytes.
  public static func verifyHex(_ hex: String, signature: [UInt8], publicKey: PublicKey) -> Bool {
    guard let bytes = Sodium.shared.utils.hex2bin(hex) else {
      return false
    }
    return verifyBytes(bytes, signature: signature, publicKey: publicKey)
  }

  /// Verify that the given signature matches the given input bytes.
  ///
  /// - Parameters:
  ///   - bytes: The bytes to check.
  ///   - signature: The proposed signature of the bytes.
  ///   - publicKey: The proposed public key.
  /// - Returns: True if the public key and signature match the given bytes.
  public static func verifyBytes(_ bytes: [UInt8], signature: [UInt8], publicKey: PublicKey) -> Bool {
    guard let bytesToVerify = prepareBytesForSigning(bytes) else {
      return false
    }

    switch publicKey.signingCurve {
    case .ed25519:
      return Sodium.shared.sign.verify(message: bytesToVerify, publicKey: publicKey.bytes, signature: signature)
    }
  }

  /// Sign the given hex encoded string with the given key.
  ///
  /// - Parameters:
  ///   - hex: The hex string to sign.
  ///   - secretKey: The secret key to sign with.
  /// - Returns: A signature from the input.
  public static func sign(hex: String, secretKey: SecretKey) -> [UInt8]? {
    guard let bytes = Sodium.shared.utils.hex2bin(hex) else {
      return nil
    }
    return self.sign(bytes: bytes, secretKey: secretKey)
  }

  /// Sign the given hex encoded string with the given key.
  ///
  /// - Parameters:
  ///   - hex: The hex string to sign.
  ///   - secretKey: The secret key to sign with.
  /// - Returns: A signature from the input.
  public static func sign(bytes: [UInt8], secretKey: SecretKey) -> [UInt8]? {
    guard let bytesToSign = prepareBytesForSigning(bytes),
          let signature = Sodium.shared.sign.signature(message: bytesToSign, secretKey: secretKey.bytes) else {
        return nil
    }
    return signature
  }

  /// Prepare bytes for signing by applying a watermark and hashing.
  public static func prepareBytesForSigning(_ bytes: [UInt8]) -> [UInt8]? {
    let watermarkedOperation = Prefix.Watermark.operation + bytes
    return Sodium.shared.genericHash.hash(message: watermarkedOperation, outputLength: 32)
  }
}
