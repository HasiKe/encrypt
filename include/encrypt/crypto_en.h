#ifndef ENCRYPT_CRYPTO_H
#define ENCRYPT_CRYPTO_H

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <array>
#include <memory>

namespace encrypt {

/**
 * @brief Encryption strength from 1 (fast) to 5 (maximum security)
 */
enum class SecurityLevel {
    LEVEL_1 = 1, // Fast but still secure (AES-128)
    LEVEL_2 = 2, // Balanced (AES-256)
    LEVEL_3 = 3, // Enhanced security (AES-256 with more iterations)
    LEVEL_4 = 4, // High security (AES-256 with Argon2)
    LEVEL_5 = 5  // Maximum security (AES-256 + ChaCha20 with Argon2id)
};

// Forward declaration
class Crypto;

/**
 * @brief Parameters for cryptographic operations
 */
struct CryptoParams {
    std::vector<uint8_t> key;        // Derived key
    std::vector<uint8_t> iv;         // Initialization vector
    std::vector<uint8_t> salt;       // Salt for key derivation
    std::vector<uint8_t> authTag;    // Authentication tag (for GCM mode)
    
    CryptoParams() = default;
    
    // Generate parameters with random values for encryption
    static CryptoParams generateForEncryption(SecurityLevel level);
    
    friend class Crypto; // Allows Crypto class access to private functions
};

/**
 * @brief Contains encryption and decryption functions
 */
class Crypto {
public:
    /**
     * @brief Encrypts a file with the given password
     * 
     * @param inputFileName Path to the input file
     * @param outputFileName Path to the output file
     * @param password Password for encryption
     * @param level Security level (1-5)
     * @param progressCallback Optional: Callback function for progress updates
     * @return true if successful, false on error
     */
    static bool encryptFile(
        const std::string& inputFileName, 
        const std::string& outputFileName, 
        const std::string& password,
        SecurityLevel level = SecurityLevel::LEVEL_2,
        const std::function<void(float)>& progressCallback = nullptr
    );

    /**
     * @brief Decrypts a file with the given password
     * 
     * @param inputFileName Path to the encrypted file
     * @param password Password for decryption
     * @param outputFileName Optional: Target filename (if not specified, original name will be used)
     * @param progressCallback Optional: Callback function for progress updates
     * @return true if successful, false on error
     */
    static bool decryptFile(
        const std::string& inputFileName, 
        const std::string& password,
        const std::string& outputFileName = "",
        const std::function<void(float)>& progressCallback = nullptr
    );
    
    /**
     * @brief Encrypts an entire folder with the given password
     * 
     * Encrypts all files in the specified folder and creates a single encrypted file.
     * 
     * @param inputFolderPath Path to the folder to encrypt
     * @param outputFileName Path to the output file
     * @param password Password for encryption
     * @param level Security level (1-5)
     * @param progressCallback Optional: Callback function for progress updates
     * @return true if successful, false on error
     */
    static bool encryptFolder(
        const std::string& inputFolderPath,
        const std::string& outputFileName,
        const std::string& password,
        SecurityLevel level = SecurityLevel::LEVEL_2,
        const std::function<void(float)>& progressCallback = nullptr
    );
    
    /**
     * @brief Decrypts an encrypted folder with the given password
     * 
     * @param inputFileName Path to the encrypted folder file
     * @param password Password for decryption
     * @param outputFolderPath Optional: Target folder path (if not specified, original folder name will be used)
     * @param progressCallback Optional: Callback function for progress updates
     * @return true if successful, false on error
     */
    static bool decryptFolder(
        const std::string& inputFileName,
        const std::string& password,
        const std::string& outputFolderPath = "",
        const std::function<void(float)>& progressCallback = nullptr
    );

    /**
     * @brief Checks password quality and returns a score
     * 
     * @param password The password to check
     * @return int Score between 0 (very weak) and 100 (very strong)
     */
    static int checkPasswordStrength(const std::string& password);

    /**
     * @brief Returns the last error message
     * 
     * @return The last error that occurred
     */
    static std::string getLastError();

    /**
     * @brief Tests the encryption functionality with a simple string
     * 
     * @param testString The string to test
     * @param level The security level to use
     * @return true if the test was successful, false otherwise
     */
    static bool testEncryption(const std::string& testString, const std::string& password, SecurityLevel level);

    // For CryptoParams
    friend CryptoParams CryptoParams::generateForEncryption(SecurityLevel level);

private:
    // Private helper functions for cryptography
    static std::vector<uint8_t> generateRandomBytes(size_t length);
    
    static CryptoParams deriveKeyFromPassword(
        const std::string& password, 
        const std::vector<uint8_t>& salt,
        SecurityLevel level
    );
    
    static bool encryptAES(
        const std::vector<uint8_t>& input, 
        std::vector<uint8_t>& output,
        const CryptoParams& params,
        SecurityLevel level
    );
    
    static bool decryptAES(
        const std::vector<uint8_t>& input, 
        std::vector<uint8_t>& output,
        const CryptoParams& params,
        SecurityLevel level
    );
    
    // For security level 5: Additional ChaCha20 encryption
    static bool encryptChaCha20(
        const std::vector<uint8_t>& input, 
        std::vector<uint8_t>& output,
        const CryptoParams& params
    );
    
    static bool decryptChaCha20(
        const std::vector<uint8_t>& input, 
        std::vector<uint8_t>& output,
        const CryptoParams& params
    );
    
    // Helper function for reading files in chunks
    static bool processFileInChunks(
        const std::string& inputFileName,
        const std::string& outputFileName,
        const std::function<bool(const std::vector<uint8_t>&, std::vector<uint8_t>&)>& processor,
        const std::function<void(float)>& progressCallback
    );
    
    // Error handling
    static thread_local std::string lastError;
};

// Constants for encryption
namespace crypto_constants {
    // File format signature
    constexpr uint8_t FILE_SIGNATURE[4] = {'S', 'E', 'C', 'F'};
    
    // Current file format version
    constexpr uint8_t FILE_VERSION = 0x01;
    
    // Header tag for security level
    constexpr uint8_t HEADER_TAG_SECURITY_LEVEL = 0x01;
    
    // Header tag for salt
    constexpr uint8_t HEADER_TAG_SALT = 0x02;
    
    // Header tag for IV
    constexpr uint8_t HEADER_TAG_IV = 0x03;
    
    // Header tag for auth tag (GCM)
    constexpr uint8_t HEADER_TAG_AUTH_TAG = 0x04;
    
    // Header tag for filename
    constexpr uint8_t HEADER_TAG_FILENAME = 0x05;
    
    // Header tag for additional ChaCha20 parameters
    constexpr uint8_t HEADER_TAG_CHACHA_NONCE = 0x06;
    
    // Header tags for folder encryption
    constexpr uint8_t HEADER_TAG_FOLDER = 0x07;
    constexpr uint8_t HEADER_TAG_FILE_ENTRY = 0x08;
    constexpr uint8_t HEADER_TAG_FILE_PATH = 0x09;
    constexpr uint8_t HEADER_TAG_FILE_SIZE = 0x0A;
    constexpr uint8_t HEADER_TAG_FILE_DATA = 0x0B;
    
    // Key lengths for different security levels
    constexpr size_t KEY_SIZE_LEVEL_1 = 16;  // 128 bit
    constexpr size_t KEY_SIZE_LEVEL_2 = 32;  // 256 bit
    constexpr size_t KEY_SIZE_LEVEL_3 = 32;  // 256 bit
    constexpr size_t KEY_SIZE_LEVEL_4 = 32;  // 256 bit
    constexpr size_t KEY_SIZE_LEVEL_5 = 32;  // 256 bit
    
    // Sizes for salt and IV
    constexpr size_t SALT_SIZE = 32;
    constexpr size_t IV_SIZE = 16;
    constexpr size_t CHACHA_NONCE_SIZE = 12;
    constexpr size_t GCM_TAG_SIZE = 16;
    
    // Iteration counts for PBKDF2 per security level
    constexpr uint32_t PBKDF2_ITERATIONS_LEVEL_1 = 10000;
    constexpr uint32_t PBKDF2_ITERATIONS_LEVEL_2 = 100000;
    constexpr uint32_t PBKDF2_ITERATIONS_LEVEL_3 = 250000;
    
    // Parameters for Argon2 (levels 4 and 5)
    constexpr uint32_t ARGON2_TIME_COST_LEVEL_4 = 3;
    constexpr uint32_t ARGON2_MEMORY_COST_LEVEL_4 = 65536; // 64 MB
    constexpr uint32_t ARGON2_PARALLELISM_LEVEL_4 = 4;
    
    constexpr uint32_t ARGON2_TIME_COST_LEVEL_5 = 4;
    constexpr uint32_t ARGON2_MEMORY_COST_LEVEL_5 = 262144; // 256 MB
    constexpr uint32_t ARGON2_PARALLELISM_LEVEL_5 = 8;
}

} // namespace encrypt

#endif // ENCRYPT_CRYPTO_H