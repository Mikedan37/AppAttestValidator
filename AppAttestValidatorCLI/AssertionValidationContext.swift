//
//  AssertionValidationContext.swift
//  AppAttestValidatorCLI
//
//  Created by Michael Danylchuk on 1/15/26.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Explicit verification inputs for assertion validation.
///
/// This context MUST be constructed explicitly.
/// If any field is missing, validation must not run.
///
/// - Note: This struct represents explicit verification inputs only.
///   It does not imply trust or make policy decisions.
public struct AssertionValidationContext {
    /// The P-256 public key used for signature verification
    let publicKey: P256.Signing.PublicKey
    
    /// CBOR-encoded Sig_structure bytes (reconstructed from assertion)
    let sigStructure: Data
    
    /// ASN.1 DER ECDSA signature bytes
    let signatureDER: Data
    
    /// Creates a validation context with explicit inputs.
    ///
    /// - Parameters:
    ///   - publicKey: The P-256 public key for verification
    ///   - sigStructure: The CBOR-encoded Sig_structure bytes (must be non-empty)
    ///   - signatureDER: The ASN.1 DER ECDSA signature (must be non-empty)
    /// - Throws: `ValidationContextError` if any required field is missing
    public init(publicKey: P256.Signing.PublicKey, sigStructure: Data, signatureDER: Data) throws {
        guard !sigStructure.isEmpty else {
            throw ValidationContextError.missingSigStructure
        }
        guard !signatureDER.isEmpty else {
            throw ValidationContextError.missingSignature
        }
        
        self.publicKey = publicKey
        self.sigStructure = sigStructure
        self.signatureDER = signatureDER
    }
    
    /// Attempts to create a context from a base64-encoded public key.
    ///
    /// - Parameters:
    ///   - publicKeyBase64: Base64-encoded public key (X.509 or raw format)
    ///   - sigStructure: The CBOR-encoded Sig_structure bytes
    ///   - signatureDER: The ASN.1 DER ECDSA signature
    /// - Returns: A validation context if the public key can be decoded, nil otherwise
    static func fromBase64PublicKey(
        _ publicKeyBase64: String,
        sigStructure: Data,
        signatureDER: Data
    ) -> AssertionValidationContext? {
        guard let keyData = Data(base64Encoded: publicKeyBase64) else {
            return nil
        }
        
        // Validate inputs
        guard !sigStructure.isEmpty else {
            return nil
        }
        guard !signatureDER.isEmpty else {
            return nil
        }
        
        // Try X.963 format first (most common for App Attest)
        if let publicKey = try? P256.Signing.PublicKey(x963Representation: keyData) {
            return try? AssertionValidationContext(
                publicKey: publicKey,
                sigStructure: sigStructure,
                signatureDER: signatureDER
            )
        }
        
        // Try X.509 DER format
        if let publicKey = try? P256.Signing.PublicKey(derRepresentation: keyData) {
            return try? AssertionValidationContext(
                publicKey: publicKey,
                sigStructure: sigStructure,
                signatureDER: signatureDER
            )
        }
        
        return nil
    }
    
    /// Attempts to create a context from a hex-encoded public key.
    ///
    /// - Parameters:
    ///   - publicKeyHex: Hex-encoded public key (X.963 format)
    ///   - sigStructure: The CBOR-encoded Sig_structure bytes
    ///   - signatureDER: The ASN.1 DER ECDSA signature
    /// - Returns: A validation context if the public key can be decoded, nil otherwise
    static func fromHexPublicKey(
        _ publicKeyHex: String,
        sigStructure: Data,
        signatureDER: Data
    ) -> AssertionValidationContext? {
        // Remove common hex prefixes
        let cleanedHex = publicKeyHex
            .replacingOccurrences(of: "0x", with: "")
            .replacingOccurrences(of: " ", with: "")
        
        // Validate inputs
        guard !sigStructure.isEmpty else {
            return nil
        }
        guard !signatureDER.isEmpty else {
            return nil
        }
        
        guard let keyData = Data(hexString: cleanedHex) else {
            return nil
        }
        
        guard let publicKey = try? P256.Signing.PublicKey(x963Representation: keyData) else {
            return nil
        }
        
        return try? AssertionValidationContext(
            publicKey: publicKey,
            sigStructure: sigStructure,
            signatureDER: signatureDER
        )
    }
    
    /// Returns a fingerprint of the public key for logging (SHA256 hash).
    var publicKeyFingerprint: String {
        let keyData = publicKey.x963Representation
        let hash = SHA256.hash(data: keyData)
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    /// Computes and returns the SHA256 hash of the Sig_structure.
    /// This is the exact hash used for signature verification.
    /// Use this to verify the validator uses the same bytes as displayed.
    var sigStructureHash: String {
        let hash = SHA256.hash(data: sigStructure)
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    /// Base64-encoded SHA256 hash of the Sig_structure.
    var sigStructureHashBase64: String {
        let hash = SHA256.hash(data: sigStructure)
        return Data(hash).base64EncodedString()
    }
}

/// Errors that can occur when constructing a validation context.
enum ValidationContextError: Error, LocalizedError {
    case missingSigStructure
    case missingSignature
    case invalidPublicKey
    
    var errorDescription: String? {
        switch self {
        case .missingSigStructure:
            return "Sig_structure bytes are required but were empty or missing"
        case .missingSignature:
            return "Signature bytes are required but were empty or missing"
        case .invalidPublicKey:
            return "Public key could not be decoded from the provided format"
        }
    }
}

// MARK: - Data Hex Extension

extension Data {
    /// Creates Data from a hex string.
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        
        var i = hexString.startIndex
        for _ in 0..<len {
            let j = hexString.index(i, offsetBy: 2)
            let bytes = hexString[i..<j]
            guard var num = UInt8(bytes, radix: 16) else {
                return nil
            }
            data.append(&num, count: 1)
            i = j
        }
        
        self = data
    }
}
