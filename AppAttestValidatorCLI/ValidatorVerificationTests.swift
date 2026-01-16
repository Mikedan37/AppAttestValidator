//
//  ValidatorVerificationTests.swift
//  AppAttestValidatorCLI
//
//  Created by Michael Danylchuk on 1/15/26.
//
//  Verification tests to ensure the validator is legit.
//  These tests verify the validator meets the "done/not done" criteria.
//

import Foundation
import CryptoKit

/// Verification tests for the assertion validator.
///
/// These tests verify:
/// 1. Validator uses exact same bytes as displayed (SHA256 match)
/// 2. Correct signature format (ASN.1 DER ECDSA)
/// 3. Correct public key usage
/// 4. Proper handling of missing context
struct ValidatorVerificationTests {
    
    // MARK: - Test 1: SHA256 Hash Match (Single Source of Truth)
    
    /// Verifies the validator computes the same SHA256 hash as displayed.
    /// This ensures the validator uses the exact same sig_structure bytes.
    ///
    /// - Parameters:
    ///   - sigStructure: The CBOR-encoded Sig_structure bytes (from display)
    ///   - displayedHash: The SHA256 hash displayed in the UI (hex)
    /// - Returns: true if hashes match, false otherwise
    static func verifyHashMatch(sigStructure: Data, displayedHash: String) -> Bool {
        let validatorHash = AssertionValidator.computeSigStructureHash(sigStructure)
        let contextHash = {
            // Create a dummy context just to get the hash property
            // (In real usage, you'd use the actual context)
            let dummyKey = try! P256.Signing.PublicKey(x963Representation: Data(repeating: 0, count: 65))
            let context = try! AssertionValidationContext(
                publicKey: dummyKey,
                sigStructure: sigStructure,
                signatureDER: Data(repeating: 0, count: 72)
            )
            return context.sigStructureHash
        }()
        
        let match = validatorHash.lowercased() == displayedHash.lowercased() &&
                    contextHash.lowercased() == displayedHash.lowercased()
        
        if !match {
            print("❌ Hash mismatch detected!")
            print("   Displayed: \(displayedHash)")
            print("   Validator: \(validatorHash)")
            print("   Context:   \(contextHash)")
        }
        
        return match
    }
    
    // MARK: - Test 2: Signature Format (ASN.1 DER ECDSA)
    
    /// Verifies the validator correctly handles ASN.1 DER signature format.
    /// Corrupting one byte should result in .failed, not crash or decode error.
    ///
    /// - Parameters:
    ///   - context: Valid validation context
    /// - Returns: true if corrupted signature is correctly rejected
    static func verifySignatureFormat(_ context: AssertionValidationContext) -> Bool {
        var corruptedSignature = context.signatureDER
        
        // Flip one byte
        if !corruptedSignature.isEmpty {
            corruptedSignature[0] ^= 0x01
        } else {
            return false
        }
        
        // Try to create context with corrupted signature
        guard let corruptedContext = try? AssertionValidationContext(
            publicKey: context.publicKey,
            sigStructure: context.sigStructure,
            signatureDER: corruptedSignature
        ) else {
            // If we can't even create the context, that's also acceptable
            // (means validation would return .cannotValidate)
            return true
        }
        
        let result = AssertionValidator.validate(corruptedContext)
        
        // Should fail verification, not crash
        switch result {
        case .verified:
            print("❌ ERROR: Corrupted signature was verified!")
            return false
        case .failed:
            print("✓ Corrupted signature correctly rejected")
            return true
        case .cannotValidate:
            // This is acceptable if DER structure became invalid
            print("⚠️ Corrupted signature cannot be validated (DER structure invalid)")
            return true
        }
    }
    
    // MARK: - Test 3: Wrong Public Key
    
    /// Verifies validation fails when using a different public key.
    ///
    /// - Parameters:
    ///   - originalContext: Context with correct key
    ///   - wrongKey: A different P-256 public key
    /// - Returns: true if wrong key is correctly rejected
    static func verifyWrongKeyRejection(
        originalContext: AssertionValidationContext,
        wrongKey: P256.Signing.PublicKey
    ) -> Bool {
        guard let wrongContext = try? AssertionValidationContext(
            publicKey: wrongKey,
            sigStructure: originalContext.sigStructure,
            signatureDER: originalContext.signatureDER
        ) else {
            return false
        }
        
        let result = AssertionValidator.validate(wrongContext)
        
        switch result {
        case .verified:
            print("❌ ERROR: Wrong key was accepted!")
            return false
        case .failed:
            print("✓ Wrong key correctly rejected")
            return true
        case .cannotValidate:
            print("⚠️ Cannot validate with wrong key")
            return true
        }
    }
    
    // MARK: - Test 4: Missing Context Handling
    
    /// Verifies the validator returns .cannotValidate when context is missing.
    ///
    /// - Returns: true if all missing context cases are handled correctly
    static func verifyMissingContextHandling() -> Bool {
        // Generate a dummy key for testing
        guard let dummyKey = try? P256.Signing.PublicKey(x963Representation: Data(repeating: 0, count: 65)) else {
            return false
        }
        
        let dummySigStructure = Data([0x84, 0xa1, 0x62, 0x68, 0x61, 0x73, 0x68]) // Minimal CBOR
        let dummySignature = Data(repeating: 0, count: 72) // Dummy DER signature
        
        // Test: Empty sig_structure
        do {
            let context = try AssertionValidationContext(
                publicKey: dummyKey,
                sigStructure: Data(), // Empty
                signatureDER: dummySignature
            )
            let result = AssertionValidator.validate(context)
            if case .cannotValidate = result {
                print("✓ Empty sig_structure correctly handled")
            } else {
                print("❌ Empty sig_structure not handled correctly")
                return false
            }
        } catch {
            print("✓ Empty sig_structure caught at context creation")
        }
        
        // Test: Empty signature
        do {
            let context = try AssertionValidationContext(
                publicKey: dummyKey,
                sigStructure: dummySigStructure,
                signatureDER: Data() // Empty
            )
            let result = AssertionValidator.validate(context)
            if case .cannotValidate = result {
                print("✓ Empty signature correctly handled")
            } else {
                print("❌ Empty signature not handled correctly")
                return false
            }
        } catch {
            print("✓ Empty signature caught at context creation")
        }
        
        return true
    }
    
    // MARK: - Test 5: Corrupted Sig_structure
    
    /// Verifies validation fails when sig_structure is corrupted.
    ///
    /// - Parameter context: Valid validation context
    /// - Returns: true if corrupted sig_structure is correctly rejected
    static func verifyCorruptedSigStructure(_ context: AssertionValidationContext) -> Bool {
        var corruptedSigStructure = context.sigStructure
        
        // Flip one byte
        if !corruptedSigStructure.isEmpty {
            corruptedSigStructure[0] ^= 0x01
        } else {
            return false
        }
        
        guard let corruptedContext = try? AssertionValidationContext(
            publicKey: context.publicKey,
            sigStructure: corruptedSigStructure,
            signatureDER: context.signatureDER
        ) else {
            return false
        }
        
        let result = AssertionValidator.validate(corruptedContext)
        
        switch result {
        case .verified:
            print("❌ ERROR: Corrupted sig_structure was verified!")
            return false
        case .failed:
            print("✓ Corrupted sig_structure correctly rejected")
            return true
        case .cannotValidate:
            print("⚠️ Cannot validate corrupted sig_structure")
            return true
        }
    }
    
    // MARK: - Full Test Suite
    
    /// Runs all verification tests.
    /// This is the "I trust it" test plan.
    ///
    /// - Parameters:
    ///   - sigStructure: The sig_structure bytes from display
    ///   - displayedHash: The SHA256 hash displayed in UI
    ///   - context: A valid validation context for testing
    ///   - wrongKey: A different public key for rejection testing
    /// - Returns: true if all tests pass
    static func runAllTests(
        sigStructure: Data,
        displayedHash: String,
        context: AssertionValidationContext,
        wrongKey: P256.Signing.PublicKey
    ) -> Bool {
        print("=== Validator Verification Tests ===\n")
        
        var allPassed = true
        
        print("Test 1: SHA256 Hash Match (Single Source of Truth)")
        if verifyHashMatch(sigStructure: sigStructure, displayedHash: displayedHash) {
            print("✅ PASSED\n")
        } else {
            print("❌ FAILED\n")
            allPassed = false
        }
        
        print("Test 2: Signature Format (ASN.1 DER ECDSA)")
        if verifySignatureFormat(context) {
            print("✅ PASSED\n")
        } else {
            print("❌ FAILED\n")
            allPassed = false
        }
        
        print("Test 3: Wrong Public Key Rejection")
        if verifyWrongKeyRejection(originalContext: context, wrongKey: wrongKey) {
            print("✅ PASSED\n")
        } else {
            print("❌ FAILED\n")
            allPassed = false
        }
        
        print("Test 4: Missing Context Handling")
        if verifyMissingContextHandling() {
            print("✅ PASSED\n")
        } else {
            print("❌ FAILED\n")
            allPassed = false
        }
        
        print("Test 5: Corrupted Sig_structure Rejection")
        if verifyCorruptedSigStructure(context) {
            print("✅ PASSED\n")
        } else {
            print("❌ FAILED\n")
            allPassed = false
        }
        
        if allPassed {
            print("=== All Tests Passed ✅ ===")
            print("The validator is legit.")
        } else {
            print("=== Some Tests Failed ❌ ===")
            print("The validator needs fixes.")
        }
        
        return allPassed
    }
}
