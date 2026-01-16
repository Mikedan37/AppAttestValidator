//
//  ValidationExample.swift
//  AppAttestValidatorCLI
//
//  Created by Michael Danylchuk on 1/15/26.
//
//  Example usage of AssertionValidator demonstrating explicit validation.
//  This shows how validation should be triggered manually with explicit context.
//

import Foundation
import CryptoKit

/// Example demonstrating explicit assertion validation.
///
/// This example shows:
/// 1. How to construct validation context explicitly
/// 2. How to trigger validation manually
/// 3. How to handle results without assuming trust
struct ValidationExample {
    
    /// Example: Validate an assertion with explicit inputs.
    ///
    /// - Parameters:
    ///   - publicKeyBase64: Base64-encoded public key
    ///   - sigStructure: CBOR-encoded Sig_structure bytes (exact bytes from display)
    ///   - signatureDER: ASN.1 DER ECDSA signature bytes
    ///   - displayedHash: Optional displayed SHA256 hash to verify match
    static func validateAssertion(
        publicKeyBase64: String,
        sigStructure: Data,
        signatureDER: Data,
        displayedHash: String? = nil
    ) {
        print("=== Cryptographic Validation (Optional) ===")
        print()
        
        // Check if we have all required inputs
        guard let context = AssertionValidationContext.fromBase64PublicKey(
            publicKeyBase64,
            sigStructure: sigStructure,
            signatureDER: signatureDER
        ) else {
            print("⚠️ Cannot validate: Missing or invalid public key, or empty sig_structure/signature")
            return
        }
        
        // Verify we're using the exact same bytes (single source of truth check)
        let validatorHash = context.sigStructureHash
        if let displayed = displayedHash {
            if validatorHash.lowercased() != displayed.lowercased() {
                print("❌ CRITICAL: Validator hash mismatch!")
                print("   Displayed: \(displayed)")
                print("   Validator: \(validatorHash)")
                print("   This indicates different sig_structure bytes were used.")
                return
            } else {
                print("✓ Hash match confirmed (single source of truth)")
            }
        }
        
        // Perform validation with logging
        let (result, logInfo) = AssertionValidator.validateWithLogging(context)
        
        // Log validation details
        print("Validation Details:")
        print("  SHA256(sig_structure): \(logInfo.sigStructureHash)")
        print("  Signature length: \(logInfo.signatureLength) bytes")
        print("  Public key fingerprint: \(logInfo.publicKeyFingerprint)")
        print()
        
        // Display result
        print("Result: \(result.description)")
        print()
        
        // Important disclaimer
        print("⚠️  Validation confirms cryptographic correctness only.")
        print("    Trust and policy decisions are external.")
    }
    
    /// Example: Validate with hex-encoded public key.
    static func validateWithHexKey(
        publicKeyHex: String,
        sigStructure: Data,
        signatureDER: Data
    ) {
        guard let context = AssertionValidationContext.fromHexPublicKey(
            publicKeyHex,
            sigStructure: sigStructure,
            signatureDER: signatureDER
        ) else {
            print("⚠️ Cannot validate: Missing or invalid public key")
            return
        }
        
        let (result, logInfo) = AssertionValidator.validateWithLogging(context)
        
        print("=== Validation Result ===")
        print("SHA256(sig_structure): \(logInfo.sigStructureHash)")
        print("Signature length: \(logInfo.signatureLength) bytes")
        print("Public key fingerprint: \(logInfo.publicKeyFingerprint)")
        print("Result: \(result.description)")
    }
    
    /// Example: Check if validation can proceed before attempting.
    /// Returns .cannotValidate with reason if any required field is missing.
    static func canValidate(
        publicKey: String?,
        sigStructure: Data?,
        signatureDER: Data?
    ) -> (canValidate: Bool, reason: String?) {
        if publicKey == nil || publicKey?.isEmpty == true {
            return (false, "Public key not provided")
        }
        
        if sigStructure == nil || sigStructure?.isEmpty == true {
            return (false, "Sig_structure bytes are empty or missing")
        }
        
        if signatureDER == nil || signatureDER?.isEmpty == true {
            return (false, "Signature bytes are empty or missing")
        }
        
        return (true, nil)
    }
    
    /// Example: Test validation with corrupted signature (flip one byte).
    /// This verifies the validator correctly detects signature mismatches.
    static func testCorruptedSignature(
        publicKeyBase64: String,
        sigStructure: Data,
        signatureDER: Data
    ) {
        print("=== Testing Corrupted Signature ===")
        
        guard let context = AssertionValidationContext.fromBase64PublicKey(
            publicKeyBase64,
            sigStructure: sigStructure,
            signatureDER: signatureDER
        ) else {
            print("⚠️ Cannot validate: Missing context")
            return
        }
        
        // Corrupt signature by flipping one byte
        var corruptedSignature = signatureDER
        if !corruptedSignature.isEmpty {
            corruptedSignature[0] ^= 0x01
        }
        
        guard let corruptedContext = AssertionValidationContext.fromBase64PublicKey(
            publicKeyBase64,
            sigStructure: sigStructure,
            signatureDER: corruptedSignature
        ) else {
            print("⚠️ Cannot create corrupted context")
            return
        }
        
        let result = AssertionValidator.validate(corruptedContext)
        
        switch result {
        case .verified:
            print("❌ ERROR: Corrupted signature was verified (this should not happen)")
        case .failed:
            print("✓ Correctly detected corrupted signature: \(result.description)")
        case .cannotValidate:
            print("⚠️ Cannot validate corrupted signature: \(result.description)")
        }
    }
}
