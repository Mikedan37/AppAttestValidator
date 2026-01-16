//
//  AssertionValidator.swift
//  AppAttestValidatorCLI
//
//  Created by Michael Danylchuk on 1/15/26.
//

import Foundation
import CryptoKit

/// Result of assertion validation.
enum AssertionValidationResult {
    /// Signature verified successfully
    case verified
    
    /// Validation failed with a specific reason
    case failed(reason: String)
    
    /// Validation cannot proceed due to missing context
    case cannotValidate(reason: String)
}

/// Cryptographic validator for App Attest assertions.
///
/// This validator performs pure cryptographic verification:
/// - Hashes the Sig_structure using SHA256
/// - Verifies the ECDSA signature using P-256
/// - Makes no trust or policy decisions
///
/// - Note: This is a forensic tool, not an authoritative verifier.
///   Validation confirms cryptographic correctness only.
struct AssertionValidator {
    
    /// Validates an assertion using the provided context.
    ///
    /// This method:
    /// 1. Hashes the Sig_structure using SHA256 (exact bytes from context)
    /// 2. Parses the ASN.1 DER signature
    /// 3. Verifies the signature against the public key
    ///
    /// - Important: This uses the exact `sigStructure` bytes from the context.
    ///   The SHA256 hash computed here must match the displayed hash for the same bytes.
    ///
    /// - Parameter context: The validation context with all required inputs
    /// - Returns: A validation result indicating success or failure
    static func validate(_ context: AssertionValidationContext) -> AssertionValidationResult {
        // Validate context has required data (defensive check)
        guard !context.sigStructure.isEmpty else {
            return .cannotValidate(reason: "Sig_structure bytes are empty")
        }
        guard !context.signatureDER.isEmpty else {
            return .cannotValidate(reason: "Signature bytes are empty")
        }
        
        // Hash the Sig_structure (exact bytes - single source of truth)
        let hash = SHA256.hash(data: context.sigStructure)
        
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
        let isValid = context.publicKey.isValidSignature(signature, for: hash)
        
        if isValid {
            return .verified
        } else {
            return .failed(reason: "Signature did not verify under the supplied public key")
        }
    }
    
    /// Computes the SHA256 hash of the Sig_structure bytes.
    /// This is the exact hash used for verification.
    /// Use this to verify the validator uses the same bytes as displayed.
    ///
    /// - Parameter sigStructure: The CBOR-encoded Sig_structure bytes
    /// - Returns: Hex-encoded SHA256 hash
    static func computeSigStructureHash(_ sigStructure: Data) -> String {
        let hash = SHA256.hash(data: sigStructure)
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    /// Validates an assertion and returns detailed logging information.
    ///
    /// - Parameter context: The validation context with all required inputs
    /// - Returns: A tuple containing the validation result and logging details
    static func validateWithLogging(_ context: AssertionValidationContext) -> (
        result: AssertionValidationResult,
        logInfo: ValidationLogInfo
    ) {
        // Use the same hash computation as validate() - single source of truth
        let hashString = context.sigStructureHash
        
        let logInfo = ValidationLogInfo(
            sigStructureHash: hashString,
            signatureLength: context.signatureDER.count,
            publicKeyFingerprint: context.publicKeyFingerprint
        )
        
        let result = validate(context)
        
        return (result, logInfo)
    }
}

/// Logging information for validation operations.
struct ValidationLogInfo {
    /// SHA256 hash of the Sig_structure (hex-encoded)
    let sigStructureHash: String
    
    /// Length of the signature in bytes
    let signatureLength: Int
    
    /// Fingerprint of the public key (SHA256 hash, hex-encoded)
    let publicKeyFingerprint: String
}

// MARK: - Validation Result Helpers

extension AssertionValidationResult {
    /// Returns a human-readable description of the result.
    var description: String {
        switch self {
        case .verified:
            return "✅ Verified"
        case .failed(let reason):
            return "❌ Failed: \(reason)"
        case .cannotValidate(let reason):
            return "⚠️ Cannot validate: \(reason)"
        }
    }
    
    /// Returns true if validation succeeded.
    var isVerified: Bool {
        if case .verified = self {
            return true
        }
        return false
    }
}
