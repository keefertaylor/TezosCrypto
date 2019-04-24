// Copyright Keefer Taylor, 2019

import Base58Swift
import CommonCrypto
import CryptoSwift
import Foundation
import Sodium

/// A static helper class that provides utility functions for cyptography.
public enum TezosCryptoUtils {
  private static let sodium: Sodium = Sodium()

  /**
   * Extract a base58check encoded public key prefixed with edpk from a given base58check encoded
   * secret key prefixed with edsk.
   */
  public static func extractPublicKey(secretKey: String) -> String? {
    guard let publicKeyBytes = self.extractPublicKeyBytes(secretKey: secretKey) else {
      return nil
    }
    return encode(message: publicKeyBytes, prefix: Prefix.Keys.public)
  }

  /**
   * Extract a base58check encoded public key hash prefixed with tz1 from a given base58check
   * encoded secret key prefixed with edsk.
   */
  public static func extractPublicKeyHash(secretKey: String) -> String? {
    guard let publicKeyBytes = self.extractPublicKeyBytes(secretKey: secretKey) else {
      return nil
    }
    return tezosPublicKeyHash(from: publicKeyBytes)
  }

  /**
   * Check that a given address is valid public key hash address.
   */
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

  /**
   * Verify that the given signature is a signed version of the given bytes by the secret key
   * associated with the given public key.
   */
  public static func verifyBytes(bytes: [UInt8], signature: [UInt8], publicKey: String) -> Bool {
    guard let decodedPublicKeyBytes = self.decodedKey(from: publicKey, prefix: Prefix.Keys.public) else {
      return false
    }
    return sodium.sign.verify(message: bytes, publicKey: decodedPublicKeyBytes, signature: signature)
  }

  /**
   * Sign a forged operation with the given secret key.
   *
   * @param operation A hex encoded string representing the forged operation
   * @param secretKey A base58check encoded secret key prefixed with 'edsk' which will sign the
   *        operation.
   * @return A OperationSigningResult with the results of the signing if successful, otherwise nil.
   */
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

  /// Generates a KeyPair given a hex-encoded seed string.
  public static func keyPair(from seedString: String) -> KeyPair? {
    guard let seed = sodium.utils.hex2bin(seedString),
      let keyPair = sodium.sign.keyPair(seed: seed) else {
      return nil
    }
    return keyPair
  }

  /**
   * Generates a Tezos public key from the given input public key.
   */
  public static func tezosPublicKey(from key: [UInt8]) -> String? {
    return encode(message: key, prefix: Prefix.Keys.public)
  }

  /**
   * Generates a Tezos private key from the given input private key.
   */
  public static func tezosSecretKey(from key: [UInt8]) -> String? {
    return encode(message: key, prefix: Prefix.Keys.secret)
  }

  /**
   * Generates a Tezos public key hash (An address) from the given input public key.
   */
  public static func tezosPublicKeyHash(from key: [UInt8]) -> String? {
    guard let hash = sodium.genericHash.hash(message: key, key: [], outputLength: 20) else {
      return ""
    }
    return encode(message: hash, prefix: Prefix.Address.tz1)
  }

  /// Encode a Base58 String from the given message and prefix.
  ///
  /// The returned address is a Base58 encoded String with the following format: [prefix][key][4 byte checksum]
  public static func encode(message: [UInt8], prefix: [UInt8]) -> String? {
    let prefixedMessage = prefix + message
    return Base58.base58CheckEncode(prefixedMessage)
  }

  /** Decode an original key from the Base58 encoded key containing a prefix and checksum. */
  private static func decodedKey(from encodedKey: String, prefix: [UInt8]) -> [UInt8]? {
    guard var decodedBytes = Base58.base58CheckDecode(encodedKey) else {
      return nil
    }

    // Decoded key will have extra bytes at the beginning for the prefix. Drop these bytes in order to get the original
    // key.
    decodedBytes.removeSubrange(0 ..< prefix.count)
    return decodedBytes
  }

  /**
   * Extract a bytes for a public key from a given base58check encoded secret key prefixed with
   * "edsk".
   */
  public static func extractPublicKeyBytes(secretKey: String) -> [UInt8]? {
    guard let decodedSecretKeyBytes = self.decodedKey(from: secretKey, prefix: Prefix.Keys.secret) else {
      return nil
    }
    return Array(decodedSecretKeyBytes[32...])
  }
}
