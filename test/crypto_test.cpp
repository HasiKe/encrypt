/**
 * @file crypto_test.cpp
 * @brief Unit tests for encryption library
 * @author HasiKe
 * @version 2.0.0
 */

#include "encrypt/crypto.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdio>

using namespace encrypt;

//=============================================================================
// Test Utilities
//=============================================================================

static int g_testsPassed = 0;
static int g_testsFailed = 0;

void testPass(const char* name) {
    std::cout << "Testing: " << name << "... \033[32mPASS\033[0m" << std::endl;
    g_testsPassed++;
}

void testFail(const char* name, const char* reason = nullptr) {
    std::cout << "Testing: " << name << "... \033[31mFAIL\033[0m";
    if (reason) std::cout << " (" << reason << ")";
    std::cout << std::endl;
    g_testsFailed++;
}

//=============================================================================
// Tests
//=============================================================================

void testVersion() {
    const char* name = "Version";
    try {
        std::string version = Crypto::getVersion();
        if (!version.empty() && version.find('.') != std::string::npos) {
            testPass(name);
        } else {
            testFail(name, "Invalid version format");
        }
    } catch (const std::exception& e) {
        testFail(name, e.what());
    }
}

void testSecurityLevelDescriptions() {
    const char* name = "SecurityLevelDescriptions";
    try {
        bool result = true;
        for (int i = 1; i <= 5; ++i) {
            auto desc = Crypto::getSecurityLevelDescription(
                static_cast<SecurityLevel>(i));
            if (desc.empty() || desc == "Unknown") {
                result = false;
                break;
            }
        }
        if (result) testPass(name);
        else testFail(name, "Missing description");
    } catch (const std::exception& e) {
        testFail(name, e.what());
    }
}

void testPasswordStrengthWeak() {
    const char* name = "PasswordStrength_Weak";
    try {
        auto analysis = Crypto::checkPasswordStrength("abc");
        if (analysis.strength == PasswordStrength::VERY_WEAK && analysis.score < 30) {
            testPass(name);
        } else {
            testFail(name, "Weak password not detected");
        }
    } catch (const std::exception& e) {
        testFail(name, e.what());
    }
}

void testPasswordStrengthStrong() {
    const char* name = "PasswordStrength_Strong";
    try {
        auto analysis = Crypto::checkPasswordStrength("MyS3cur3P@ssw0rd!2024");
        if (analysis.strength == PasswordStrength::STRONG && analysis.score >= 90) {
            testPass(name);
        } else {
            testFail(name, "Strong password not recognized");
        }
    } catch (const std::exception& e) {
        testFail(name, e.what());
    }
}

void testPasswordStrengthCriteria() {
    const char* name = "PasswordStrength_Criteria";
    try {
        auto analysis = Crypto::checkPasswordStrength("Aa1!");
        if (analysis.hasLowercase && analysis.hasUppercase &&
            analysis.hasDigits && analysis.hasSpecial && !analysis.hasSufficientLength) {
            testPass(name);
        } else {
            testFail(name, "Criteria check failed");
        }
    } catch (const std::exception& e) {
        testFail(name, e.what());
    }
}

void testEncryptionLevel1() {
    const char* name = "Encryption_Level1";
    try {
        if (Crypto::testEncryption(SecurityLevel::LEVEL_1)) {
            testPass(name);
        } else {
            testFail(name);
        }
    } catch (const std::exception& e) {
        testFail(name, e.what());
    }
}

void testEncryptionLevel2() {
    const char* name = "Encryption_Level2";
    try {
        if (Crypto::testEncryption(SecurityLevel::LEVEL_2)) {
            testPass(name);
        } else {
            testFail(name);
        }
    } catch (const std::exception& e) {
        testFail(name, e.what());
    }
}

void testEncryptionLevel3() {
    const char* name = "Encryption_Level3";
    try {
        if (Crypto::testEncryption(SecurityLevel::LEVEL_3)) {
            testPass(name);
        } else {
            testFail(name);
        }
    } catch (const std::exception& e) {
        testFail(name, e.what());
    }
}

void testEncryptionLevel4() {
    const char* name = "Encryption_Level4";
    try {
        if (Crypto::testEncryption(SecurityLevel::LEVEL_4)) {
            testPass(name);
        } else {
            testFail(name);
        }
    } catch (const std::exception& e) {
        testFail(name, e.what());
    }
}

void testEncryptionLevel5() {
    const char* name = "Encryption_Level5";
    try {
        if (Crypto::testEncryption(SecurityLevel::LEVEL_5)) {
            testPass(name);
        } else {
            testFail(name);
        }
    } catch (const std::exception& e) {
        testFail(name, e.what());
    }
}

void testFileEncryptDecrypt() {
    const char* name = "FileEncryptDecrypt";
    std::string testPath = "/tmp/encrypt_test.txt";
    std::string encPath;
    
    try {
        std::string testData = "This is test data for encryption/decryption.\n"
                               "It contains multiple lines.\n"
                               "With various characters: äöü ñ 中文";
        
        // Create test file
        {
            std::ofstream out(testPath);
            out << testData;
        }
        
        // Encrypt
        auto encResult = Crypto::encryptFile(testPath, "TestPassword123!",
                                             SecurityLevel::LEVEL_2);
        
        if (!encResult.success) {
            std::remove(testPath.c_str());
            testFail(name, encResult.errorMessage.c_str());
            return;
        }
        
        encPath = encResult.outputPath;
        
        // Remove original
        std::remove(testPath.c_str());
        
        // Decrypt
        auto decResult = Crypto::decryptFile(encPath, "TestPassword123!");
        
        if (!decResult.success) {
            std::remove(encPath.c_str());
            testFail(name, decResult.errorMessage.c_str());
            return;
        }
        
        // Verify content
        std::ifstream in(decResult.outputPath);
        std::string decrypted((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
        in.close();
        
        // Cleanup
        std::remove(decResult.outputPath.c_str());
        std::remove(encPath.c_str());
        
        if (decrypted == testData) {
            testPass(name);
        } else {
            testFail(name, "Content mismatch");
        }
    } catch (const std::exception& e) {
        std::remove(testPath.c_str());
        if (!encPath.empty()) std::remove(encPath.c_str());
        testFail(name, e.what());
    }
}

void testWrongPassword() {
    const char* name = "WrongPassword";
    std::string testPath = "/tmp/encrypt_test_wrong.txt";
    std::string encPath;
    
    try {
        // Create test file
        {
            std::ofstream out(testPath);
            out << "Test data";
        }
        
        // Encrypt
        auto encResult = Crypto::encryptFile(testPath, "CorrectPassword",
                                             SecurityLevel::LEVEL_2);
        
        if (!encResult.success) {
            std::remove(testPath.c_str());
            testFail(name, "Encryption failed");
            return;
        }
        
        encPath = encResult.outputPath;
        std::remove(testPath.c_str());
        
        // Try decrypt with wrong password
        auto decResult = Crypto::decryptFile(encPath, "WrongPassword");
        
        // Cleanup
        std::remove(encPath.c_str());
        if (decResult.success) {
            std::remove(decResult.outputPath.c_str());
        }
        
        if (!decResult.success) {
            testPass(name);
        } else {
            testFail(name, "Decryption should have failed");
        }
    } catch (const std::exception& e) {
        std::remove(testPath.c_str());
        if (!encPath.empty()) std::remove(encPath.c_str());
        testFail(name, e.what());
    }
}

void testIsEncryptedFile() {
    const char* name = "IsEncryptedFile";
    std::string testPath = "/tmp/encrypt_test_check.txt";
    std::string encPath;
    
    try {
        // Create test file
        {
            std::ofstream out(testPath);
            out << "Not encrypted";
        }
        
        bool notEncrypted = !Crypto::isEncryptedFile(testPath);
        
        // Encrypt it
        auto encResult = Crypto::encryptFile(testPath, "TestPassword",
                                             SecurityLevel::LEVEL_2);
        
        if (!encResult.success) {
            std::remove(testPath.c_str());
            testFail(name, "Encryption failed");
            return;
        }
        
        encPath = encResult.outputPath;
        bool isEncrypted = Crypto::isEncryptedFile(encPath);
        
        // Cleanup
        std::remove(testPath.c_str());
        std::remove(encPath.c_str());
        
        if (notEncrypted && isEncrypted) {
            testPass(name);
        } else {
            testFail(name, "Detection failed");
        }
    } catch (const std::exception& e) {
        std::remove(testPath.c_str());
        if (!encPath.empty()) std::remove(encPath.c_str());
        testFail(name, e.what());
    }
}

void testReadHeader() {
    const char* name = "ReadHeader";
    std::string testPath = "/tmp/encrypt_test_header.txt";
    std::string encPath;
    
    try {
        // Create and encrypt test file
        {
            std::ofstream out(testPath);
            out << "Header test data";
        }
        
        auto encResult = Crypto::encryptFile(testPath, "TestPassword",
                                             SecurityLevel::LEVEL_3);
        
        if (!encResult.success) {
            std::remove(testPath.c_str());
            testFail(name, "Encryption failed");
            return;
        }
        
        encPath = encResult.outputPath;
        
        // Read header
        auto params = Crypto::readFileHeader(encPath);
        
        bool result = (params.level == SecurityLevel::LEVEL_3) &&
                      (params.salt.size() == Constants::SALT_SIZE) &&
                      (params.iv.size() == Constants::IV_SIZE) &&
                      !params.originalFilename.empty();
        
        // Cleanup
        std::remove(testPath.c_str());
        std::remove(encPath.c_str());
        
        if (result) {
            testPass(name);
        } else {
            testFail(name, "Header data mismatch");
        }
    } catch (const std::exception& e) {
        std::remove(testPath.c_str());
        if (!encPath.empty()) std::remove(encPath.c_str());
        testFail(name, e.what());
    }
}

//=============================================================================
// Main
//=============================================================================

int main() {
    std::cout << "\n=== Encrypt Library Test Suite ===\n" << std::endl;
    
    // Basic tests
    testVersion();
    testSecurityLevelDescriptions();
    
    // Password strength tests
    testPasswordStrengthWeak();
    testPasswordStrengthStrong();
    testPasswordStrengthCriteria();
    
    // Encryption tests
    testEncryptionLevel1();
    testEncryptionLevel2();
    testEncryptionLevel3();
    testEncryptionLevel4();
    testEncryptionLevel5();
    
    // File operation tests
    testFileEncryptDecrypt();
    testWrongPassword();
    testIsEncryptedFile();
    testReadHeader();
    
    // Summary
    std::cout << "\n=== Test Results ===" << std::endl;
    std::cout << "Passed: \033[32m" << g_testsPassed << "\033[0m" << std::endl;
    std::cout << "Failed: \033[31m" << g_testsFailed << "\033[0m" << std::endl;
    std::cout << "Total:  " << (g_testsPassed + g_testsFailed) << std::endl;
    
    return g_testsFailed > 0 ? 1 : 0;
}
