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
#include <cassert>

using namespace encrypt;

//=============================================================================
// Test Utilities
//=============================================================================

static int g_testsPassed = 0;
static int g_testsFailed = 0;

#define TEST(name) \
    std::cout << "Testing: " << #name << "... "; \
    try {

#define TEST_END(condition) \
        if (condition) { \
            std::cout << "\033[32mPASS\033[0m" << std::endl; \
            g_testsPassed++; \
        } else { \
            std::cout << "\033[31mFAIL\033[0m" << std::endl; \
            g_testsFailed++; \
        } \
    } catch (const std::exception& e) { \
        std::cout << "\033[31mEXCEPTION: " << e.what() << "\033[0m" << std::endl; \
        g_testsFailed++; \
    }

//=============================================================================
// Tests
//=============================================================================

void testVersion() {
    TEST(Version)
    std::string version = Crypto::getVersion();
    bool result = !version.empty() && version.find('.') != std::string::npos;
    TEST_END(result)
}

void testSecurityLevelDescriptions() {
    TEST(SecurityLevelDescriptions)
    bool result = true;
    for (int i = 1; i <= 5; ++i) {
        auto desc = Crypto::getSecurityLevelDescription(
            static_cast<SecurityLevel>(i));
        if (desc.empty() || desc == "Unknown") {
            result = false;
            break;
        }
    }
    TEST_END(result)
}

void testPasswordStrengthWeak() {
    TEST(PasswordStrength_Weak)
    auto analysis = Crypto::checkPasswordStrength("abc");
    bool result = analysis.strength == PasswordStrength::VERY_WEAK &&
                  analysis.score < 30;
    TEST_END(result)
}

void testPasswordStrengthStrong() {
    TEST(PasswordStrength_Strong)
    auto analysis = Crypto::checkPasswordStrength("MyS3cur3P@ssw0rd!2024");
    bool result = analysis.strength == PasswordStrength::STRONG &&
                  analysis.score >= 90;
    TEST_END(result)
}

void testPasswordStrengthCriteria() {
    TEST(PasswordStrength_Criteria)
    auto analysis = Crypto::checkPasswordStrength("Aa1!");
    bool result = analysis.hasLowercase &&
                  analysis.hasUppercase &&
                  analysis.hasDigits &&
                  analysis.hasSpecial &&
                  !analysis.hasSufficientLength;
    TEST_END(result)
}

void testEncryptionLevel1() {
    TEST(Encryption_Level1)
    bool result = Crypto::testEncryption(SecurityLevel::LEVEL_1);
    TEST_END(result)
}

void testEncryptionLevel2() {
    TEST(Encryption_Level2)
    bool result = Crypto::testEncryption(SecurityLevel::LEVEL_2);
    TEST_END(result)
}

void testEncryptionLevel3() {
    TEST(Encryption_Level3)
    bool result = Crypto::testEncryption(SecurityLevel::LEVEL_3);
    TEST_END(result)
}

void testEncryptionLevel4() {
    TEST(Encryption_Level4)
    bool result = Crypto::testEncryption(SecurityLevel::LEVEL_4);
    TEST_END(result)
}

void testEncryptionLevel5() {
    TEST(Encryption_Level5)
    bool result = Crypto::testEncryption(SecurityLevel::LEVEL_5);
    TEST_END(result)
}

void testFileEncryptDecrypt() {
    TEST(FileEncryptDecrypt)
    
    // Create test file
    std::string testPath = "/tmp/encrypt_test.txt";
    std::string testData = "This is test data for encryption/decryption.\n"
                           "It contains multiple lines.\n"
                           "With various characters: äöü ñ 中文 🔐";
    
    {
        std::ofstream out(testPath);
        out << testData;
    }
    
    // Encrypt
    auto encResult = Crypto::encryptFile(testPath, "TestPassword123!",
                                         SecurityLevel::LEVEL_2);
    
    if (!encResult.success) {
        std::cout << "Encrypt failed: " << encResult.errorMessage << " ";
        TEST_END(false)
        return;
    }
    
    // Remove original
    std::remove(testPath.c_str());
    
    // Decrypt
    auto decResult = Crypto::decryptFile(encResult.outputPath, "TestPassword123!");
    
    if (!decResult.success) {
        std::cout << "Decrypt failed: " << decResult.errorMessage << " ";
        std::remove(encResult.outputPath.c_str());
        TEST_END(false)
        return;
    }
    
    // Verify content
    std::ifstream in(decResult.outputPath);
    std::string decrypted((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
    
    bool result = (decrypted == testData);
    
    // Cleanup
    std::remove(testPath.c_str());
    std::remove(encResult.outputPath.c_str());
    
    TEST_END(result)
}

void testWrongPassword() {
    TEST(WrongPassword)
    
    // Create test file
    std::string testPath = "/tmp/encrypt_test_wrong.txt";
    {
        std::ofstream out(testPath);
        out << "Test data";
    }
    
    // Encrypt
    auto encResult = Crypto::encryptFile(testPath, "CorrectPassword",
                                         SecurityLevel::LEVEL_2);
    
    if (!encResult.success) {
        TEST_END(false)
        return;
    }
    
    // Try decrypt with wrong password
    auto decResult = Crypto::decryptFile(encResult.outputPath, "WrongPassword");
    
    bool result = !decResult.success;
    
    // Cleanup
    std::remove(testPath.c_str());
    std::remove(encResult.outputPath.c_str());
    
    TEST_END(result)
}

void testIsEncryptedFile() {
    TEST(IsEncryptedFile)
    
    // Create test file
    std::string testPath = "/tmp/encrypt_test_check.txt";
    {
        std::ofstream out(testPath);
        out << "Not encrypted";
    }
    
    bool notEncrypted = !Crypto::isEncryptedFile(testPath);
    
    // Encrypt it
    auto encResult = Crypto::encryptFile(testPath, "TestPassword",
                                         SecurityLevel::LEVEL_2);
    
    bool isEncrypted = Crypto::isEncryptedFile(encResult.outputPath);
    
    // Cleanup
    std::remove(testPath.c_str());
    std::remove(encResult.outputPath.c_str());
    
    bool result = notEncrypted && isEncrypted;
    TEST_END(result)
}

void testReadHeader() {
    TEST(ReadHeader)
    
    // Create and encrypt test file
    std::string testPath = "/tmp/encrypt_test_header.txt";
    {
        std::ofstream out(testPath);
        out << "Header test data";
    }
    
    auto encResult = Crypto::encryptFile(testPath, "TestPassword",
                                         SecurityLevel::LEVEL_3);
    
    if (!encResult.success) {
        TEST_END(false)
        return;
    }
    
    // Read header
    auto params = Crypto::readFileHeader(encResult.outputPath);
    
    bool result = (params.level == SecurityLevel::LEVEL_3) &&
                  (params.salt.size() == Constants::SALT_SIZE) &&
                  (params.iv.size() == Constants::IV_SIZE) &&
                  !params.originalFilename.empty();
    
    // Cleanup
    std::remove(testPath.c_str());
    std::remove(encResult.outputPath.c_str());
    
    TEST_END(result)
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
