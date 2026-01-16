//
//  ServerAssertionValidator.swift
//  AppAttestValidatorCLI
//
//  Created by Michael Danylchuk on 1/15/26.
//
//  Server-side assertion validator.
//  Pure, stateless, platform-agnostic cryptographic verification.
//

import Foundation
import CryptoKit

// MARK: - Server Validation Context

/// Server-side validation context with raw Data inputs.
///
/// This context requires explicit inputs in their raw form:
/// - sigStructure: CBOR-encoded Sig_structure bytes (must be passed in, not reconstructed)
/// - signatureDER: ASN.1 DER ECDSA signature bytes
/// - publicKey: Uncompressed P-256 public key (65 bytes: 0x04 || X || Y)
///
/// - Important: This validator does NOT reconstruct sigStructure.
///   It must be provided exactly as computed by the decoder.
struct ServerAssertionValidationContext {
    /// CBOR-encoded Sig_structure bytes (reconstructed from assertion)
    let sigStructure: Data
    
    /// ASN.1 DER ECDSA signature bytes
    let signatureDER: Data
    
    /// Uncompressed P-256 public key (65 bytes: 0x04 || X || Y)
    let publicKey: Data
    
    /// Creates a validation context with raw Data inputs.
    ///
    /// - Parameters:
    ///   - sigStructure: CBOR-encoded Sig_structure bytes
    ///   - signatureDER: ASN.1 DER ECDSA signature bytes
    ///   - publicKey: Uncompressed P-256 public key (65 bytes: 0x04 || X || Y)
    /// - Returns: A validation context if all inputs are valid, nil otherwise
    static func create(
        sigStructure: Data,
        signatureDER: Data,
        publicKey: Data
    ) -> ServerAssertionValidationContext? {
        // Validate sigStructure is non-empty
        guard !sigStructure.isEmpty else {
            return nil
        }
        
        // Validate signature is non-empty
        guard !signatureDER.isEmpty else {
            return nil
        }
        
        // Validate public key format: must be 65 bytes, starting with 0x04
        guard publicKey.count == 65 else {
            return nil
        }
        guard publicKey[0] == 0x04 else {
            return nil
        }
        
        return ServerAssertionValidationContext(
            sigStructure: sigStructure,
            signatureDER: signatureDER,
            publicKey: publicKey
        )
    }
    
    /// Computes SHA256 hash of the Sig_structure.
    /// This is the exact hash used for signature verification.
    var sigStructureHash: Data {
        SHA256.hash(data: sigStructure)
    }
    
    /// Hex-encoded SHA256 hash of the Sig_structure (for logging).
    var sigStructureHashHex: String {
        sigStructureHash.map { String(format: "%02x", $0) }.joined()
    }
    
    /// Public key fingerprint (SHA256 hash, hex-encoded, for logging).
    var publicKeyFingerprint: String {
        let hash = SHA256.hash(data: publicKey)
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    /// Converts the raw public key to CryptoKit's P256.Signing.PublicKey.
    /// This is an internal helper for verification.
    private var cryptoKitPublicKey: P256.Signing.PublicKey? {
        // The public key is already in X9.63 format (0x04 || X || Y)
        // CryptoKit expects X9.63 format, so we can use it directly
        return try? P256.Signing.PublicKey(x963Representation: publicKey)
    }
}

// MARK: - Server Validation Result

/// Result of server-side assertion validation.
enum ServerAssertionValidationResult {
    /// Signature verified successfully
    case verified
    
    /// Cryptographic verification failed
    case failed(reason: String)
    
    /// Validation cannot proceed due to missing or invalid context
    case cannotValidate(reason: String)
    
    /// Returns true if validation succeeded.
    var isVerified: Bool {
        if case .verified = self {
            return true
        }
        return false
    }
    
    /// Human-readable description (for logging).
    var description: String {
        switch self {
        case .verified:
            return "Verified"
        case .failed(let reason):
            return "Failed: \(reason)"
        case .cannotValidate(let reason):
            return "Cannot validate: \(reason)"
        }
    }
}

// MARK: - Server Assertion Validator

/// Pure, stateless server-side validator for App Attest assertions.
///
/// This validator:
/// - Verifies ECDSA signature over SHA256(sig_structure)
/// - Uses P-256 cryptography
/// - Makes no trust or policy decisions
/// - Never reconstructs sigStructure (must be provided)
/// - Never fetches keys or reads files
///
/// - Note: This is a cryptographic verification tool only.
///   Trust and policy decisions are external.
struct ServerAssertionValidator {
    
    /// Validates an assertion using the provided context.
    ///
    /// This method:
    /// 1. Validates input formats
    /// 2. Hashes the Sig_structure using SHA256 (exact bytes from context)
    /// 3. Parses the ASN.1 DER signature
    /// 4. Verifies the signature against the public key
    ///
    /// - Important: This uses the exact `sigStructure` bytes from the context.
    ///   The SHA256 hash computed here must match the hash computed during decoding.
    ///
    /// - Parameter context: The validation context with all required inputs
    /// - Returns: A validation result indicating success or failure
    static func validate(context: ServerAssertionValidationContext) -> ServerAssertionValidationResult {
        // Validate context has required data (defensive check)
        guard !context.sigStructure.isEmpty else {
            return .cannotValidate(reason: "Sig_structure bytes are empty")
        }
        guard !context.signatureDER.isEmpty else {
            return .cannotValidate(reason: "Signature bytes are empty")
        }
        guard context.publicKey.count == 65, context.publicKey[0] == 0x04 else {
            return .cannotValidate(reason: "Public key must be 65 bytes uncompressed format (0x04 || X || Y)")
        }
        
        // Convert raw public key to CryptoKit format
        guard let publicKey = context.cryptoKitPublicKey else {
            return .cannotValidate(reason: "Public key is not a valid P-256 key")
        }
        
        // Hash the Sig_structure (exact bytes - single source of truth)
        let hash = context.sigStructureHash
        
        // Parse the ASN.1 DER signature
        let signature: P256.Signing.ECDSASignature
        do {
            signature = try P256.Signing.ECDSASignature(derRepresentation: context.signatureDER)
        } catch {
            // If DER structure is invalid, return failed (not cannotValidate)
            // because the signature exists but is malformed
            return .failed(reason: "Failed to parse ASN.1 DER signature: \(error.localizedDescription)")
        }
        
        // Verify the signature
        let isValid = publicKey.isValidSignature(signature, for: hash)
        
        if isValid {
            return .verified
        } else {
            return .failed(reason: "Signature did not verify under the supplied public key")
        }
    }
}

// MARK: - Validation Logging Info

/// Logging information for server-side validation operations.
///
/// Contains only safe-to-log information:
/// - Hash values (not raw data)
/// - Lengths (not content)
/// - Fingerprints (not keys)
struct ServerValidationLogInfo {
    /// SHA256 hash of the Sig_structure (hex-encoded)
    let sigStructureHash: String
    
    /// Length of the signature in bytes
    let signatureLength: Int
    
    /// Fingerprint of the public key (SHA256 hash, hex-encoded)
    let publicKeyFingerprint: String
    
    /// Creates logging info from a validation context.
    init(context: ServerAssertionValidationContext) {
        self.sigStructureHash = context.sigStructureHashHex
        self.signatureLength = context.signatureDER.count
        self.publicKeyFingerprint = context.publicKeyFingerprint
    }
}

// MARK: - Convenience Extension

extension ServerAssertionValidator {
    /// Validates an assertion and returns detailed logging information.
    ///
    /// - Parameter context: The validation context with all required inputs
    /// - Returns: A tuple containing the validation result and logging details
    static func validateWithLogging(context: ServerAssertionValidationContext) -> (
        result: ServerAssertionValidationResult,
        logInfo: ServerValidationLogInfo
    ) {
        let logInfo = ServerValidationLogInfo(context: context)
        let result = validate(context: context)
        
        return (result, logInfo)
    }
}
