/**
 * @file crypto.h
 * @brief Military-grade file encryption library
 * @author HasiKe
 * @version 2.0.0
 * @date 2026
 * 
 * @copyright MIT License
 * 
 * Core cryptographic interface for the Encrypt library.
 * Provides AES-256-GCM and ChaCha20-Poly1305 encryption with
 * multiple security levels and key derivation functions.
 */

#ifndef ENCRYPT_CRYPTO_H
#define ENCRYPT_CRYPTO_H

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>

namespace encrypt {

//=============================================================================
// Constants
//=============================================================================

/**
 * @namespace Constants
 * @brief Cryptographic constants and configuration values
 */
namespace Constants {
    // Version
    constexpr uint8_t VERSION_MAJOR = 2;
    constexpr uint8_t VERSION_MINOR = 0;
    constexpr uint8_t VERSION_PATCH = 0;
    
    // File signature
    constexpr char FILE_SIGNATURE[] = "SECF";
    constexpr size_t FILE_SIGNATURE_SIZE = 4;
    constexpr uint8_t FILE_VERSION = 0x01;
    
    // Key sizes (bytes)
    constexpr size_t AES_128_KEY_SIZE = 16;
    constexpr size_t AES_256_KEY_SIZE = 32;
    constexpr size_t CHACHA20_KEY_SIZE = 32;
    constexpr size_t SALT_SIZE = 32;
    constexpr size_t IV_SIZE = 16;          // AES-GCM
    constexpr size_t CHACHA_IV_SIZE = 24;   // XChaCha20
    constexpr size_t AUTH_TAG_SIZE = 16;
    
    // Processing
    constexpr size_t CHUNK_SIZE = 65536;    // 64 KB
    constexpr size_t MAX_FILENAME_SIZE = 4096;
    
    // TLV Tags
    constexpr uint8_t TAG_SECURITY_LEVEL = 0x01;
    constexpr uint8_t TAG_SALT = 0x02;
    constexpr uint8_t TAG_IV = 0x03;
    constexpr uint8_t TAG_AUTH_TAG = 0x04;
    constexpr uint8_t TAG_FILENAME = 0x05;
    constexpr uint8_t TAG_CHECKSUM = 0x06;
    constexpr uint8_t TAG_FOLDER_FLAG = 0x07;
    constexpr uint8_t TAG_FILE_COUNT = 0x08;
    constexpr uint8_t TAG_TOTAL_SIZE = 0x09;
    constexpr uint8_t TAG_TIMESTAMP = 0x0A;
    constexpr uint8_t TAG_METADATA = 0x0B;
    constexpr uint8_t TAG_END = 0x00;
    
    // Password strength thresholds
    constexpr int PASSWORD_MIN_LENGTH = 8;
    constexpr int PASSWORD_STRENGTH_WEAK = 25;
    constexpr int PASSWORD_STRENGTH_FAIR = 50;
    constexpr int PASSWORD_STRENGTH_GOOD = 75;
    constexpr int PASSWORD_STRENGTH_STRONG = 90;
    
    // File extension
    constexpr char ENCRYPTED_EXTENSION[] = ".cryp";
}

//=============================================================================
// Enums
//=============================================================================

/**
 * @enum SecurityLevel
 * @brief Available encryption security levels
 * 
 * Higher levels provide stronger security but require more
 * computational resources for key derivation.
 */
enum class SecurityLevel : uint8_t {
    /** AES-128-GCM, PBKDF2 10K iterations - Fast, basic protection */
    LEVEL_1 = 1,
    
    /** AES-256-GCM, PBKDF2 100K iterations - Recommended default */
    LEVEL_2 = 2,
    
    /** AES-256-GCM, PBKDF2 250K iterations - Enhanced security */
    LEVEL_3 = 3,
    
    /** AES-256-GCM, Argon2id 64MB - High security, memory-hard */
    LEVEL_4 = 4,
    
    /** AES-256 + ChaCha20, Argon2id 256MB - Maximum security */
    LEVEL_5 = 5
};

/**
 * @enum PasswordStrength
 * @brief Password strength classification
 */
enum class PasswordStrength {
    VERY_WEAK,  ///< Score < 25
    WEAK,       ///< Score 25-49
    FAIR,       ///< Score 50-74
    GOOD,       ///< Score 75-89
    STRONG      ///< Score >= 90
};

//=============================================================================
// Structures
//=============================================================================

/**
 * @struct CryptoParams
 * @brief Cryptographic parameters for encryption/decryption
 */
struct CryptoParams {
    SecurityLevel level;                ///< Security level
    std::vector<uint8_t> salt;          ///< Random salt for KDF
    std::vector<uint8_t> iv;            ///< Initialization vector
    std::vector<uint8_t> authTag;       ///< Authentication tag
    std::string originalFilename;       ///< Original filename before encryption
    bool isFolder;                      ///< True if encrypted folder
    uint32_t fileCount;                 ///< Number of files (for folders)
    uint64_t totalSize;                 ///< Total uncompressed size
    int64_t timestamp;                  ///< Unix timestamp of encryption
    
    CryptoParams() : level(SecurityLevel::LEVEL_2), isFolder(false), 
                     fileCount(0), totalSize(0), timestamp(0) {}
};

/**
 * @struct PasswordAnalysis
 * @brief Detailed password strength analysis
 */
struct PasswordAnalysis {
    int score;                          ///< Overall score (0-100)
    PasswordStrength strength;          ///< Strength classification
    bool hasLowercase;                  ///< Contains lowercase letters
    bool hasUppercase;                  ///< Contains uppercase letters
    bool hasDigits;                     ///< Contains digits
    bool hasSpecial;                    ///< Contains special characters
    bool hasSufficientLength;           ///< Meets minimum length
    std::string feedback;               ///< Human-readable feedback
};

/**
 * @struct EncryptionResult
 * @brief Result of an encryption/decryption operation
 */
struct EncryptionResult {
    bool success;                       ///< Operation succeeded
    std::string outputPath;             ///< Path to output file
    std::string errorMessage;           ///< Error message if failed
    uint64_t bytesProcessed;            ///< Total bytes processed
    double elapsedSeconds;              ///< Time taken
    
    EncryptionResult() : success(false), bytesProcessed(0), elapsedSeconds(0) {}
};

//=============================================================================
// Callback Types
//=============================================================================

/**
 * @brief Progress callback function type
 * @param current Current bytes processed
 * @param total Total bytes to process
 * @param filename Current file being processed
 * @return false to cancel operation
 */
using ProgressCallback = std::function<bool(uint64_t current, uint64_t total, 
                                            const std::string& filename)>;

//=============================================================================
// Exceptions
//=============================================================================

/**
 * @class CryptoException
 * @brief Base exception for cryptographic errors
 */
class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& message) 
        : std::runtime_error(message) {}
};

/**
 * @class InvalidPasswordException
 * @brief Thrown when password is incorrect or invalid
 */
class InvalidPasswordException : public CryptoException {
public:
    InvalidPasswordException() 
        : CryptoException("Invalid password or corrupted file") {}
};

/**
 * @class FileFormatException
 * @brief Thrown when file format is invalid
 */
class FileFormatException : public CryptoException {
public:
    explicit FileFormatException(const std::string& message)
        : CryptoException("Invalid file format: " + message) {}
};

//=============================================================================
// Main Crypto Class
//=============================================================================

/**
 * @class Crypto
 * @brief Main encryption/decryption interface
 * 
 * Provides static methods for file and folder encryption using
 * multiple security levels. Thread-safe for concurrent operations.
 * 
 * @example Basic usage
 * @code
 * // Encrypt a file with default security
 * auto result = Crypto::encryptFile("secret.pdf", "MyP@ssw0rd!");
 * 
 * // Encrypt with maximum security
 * auto result = Crypto::encryptFile("secret.pdf", "MyP@ssw0rd!", 
 *                                   SecurityLevel::LEVEL_5);
 * 
 * // Decrypt
 * auto result = Crypto::decryptFile("secret.pdf.cryp", "MyP@ssw0rd!");
 * @endcode
 */
class Crypto {
public:
    //-------------------------------------------------------------------------
    // File Operations
    //-------------------------------------------------------------------------
    
    /**
     * @brief Encrypt a single file
     * @param inputPath Path to file to encrypt
     * @param password Encryption password
     * @param level Security level (default: LEVEL_2)
     * @param outputPath Custom output path (optional)
     * @param progress Progress callback (optional)
     * @return EncryptionResult with operation status
     */
    static EncryptionResult encryptFile(
        const std::string& inputPath,
        const std::string& password,
        SecurityLevel level = SecurityLevel::LEVEL_2,
        const std::string& outputPath = "",
        ProgressCallback progress = nullptr
    );
    
    /**
     * @brief Decrypt a single file
     * @param inputPath Path to encrypted file (.cryp)
     * @param password Decryption password
     * @param outputPath Custom output path (optional)
     * @param progress Progress callback (optional)
     * @return EncryptionResult with operation status
     */
    static EncryptionResult decryptFile(
        const std::string& inputPath,
        const std::string& password,
        const std::string& outputPath = "",
        ProgressCallback progress = nullptr
    );
    
    //-------------------------------------------------------------------------
    // Folder Operations
    //-------------------------------------------------------------------------
    
    /**
     * @brief Encrypt an entire folder recursively
     * @param folderPath Path to folder to encrypt
     * @param password Encryption password
     * @param level Security level (default: LEVEL_2)
     * @param outputPath Custom output path (optional)
     * @param progress Progress callback (optional)
     * @return EncryptionResult with operation status
     */
    static EncryptionResult encryptFolder(
        const std::string& folderPath,
        const std::string& password,
        SecurityLevel level = SecurityLevel::LEVEL_2,
        const std::string& outputPath = "",
        ProgressCallback progress = nullptr
    );
    
    /**
     * @brief Decrypt a folder archive
     * @param inputPath Path to encrypted folder (.cryp)
     * @param password Decryption password
     * @param outputPath Custom output directory (optional)
     * @param progress Progress callback (optional)
     * @return EncryptionResult with operation status
     */
    static EncryptionResult decryptFolder(
        const std::string& inputPath,
        const std::string& password,
        const std::string& outputPath = "",
        ProgressCallback progress = nullptr
    );
    
    //-------------------------------------------------------------------------
    // Utilities
    //-------------------------------------------------------------------------
    
    /**
     * @brief Analyze password strength
     * @param password Password to analyze
     * @return Detailed password analysis
     */
    static PasswordAnalysis checkPasswordStrength(const std::string& password);
    
    /**
     * @brief Test encryption with sample data
     * @param level Security level to test
     * @return true if encryption subsystem works correctly
     */
    static bool testEncryption(SecurityLevel level = SecurityLevel::LEVEL_2);
    
    /**
     * @brief Read file header without decrypting
     * @param inputPath Path to encrypted file
     * @return CryptoParams with file metadata
     * @throws FileFormatException if file is invalid
     */
    static CryptoParams readFileHeader(const std::string& inputPath);
    
    /**
     * @brief Check if file is encrypted by this library
     * @param inputPath Path to file
     * @return true if file has valid encryption header
     */
    static bool isEncryptedFile(const std::string& inputPath);
    
    /**
     * @brief Get security level description
     * @param level Security level
     * @return Human-readable description
     */
    static std::string getSecurityLevelDescription(SecurityLevel level);
    
    /**
     * @brief Get version string
     * @return Version in format "X.Y.Z"
     */
    static std::string getVersion();

private:
    // Internal implementation
    static std::vector<uint8_t> deriveKey(
        const std::string& password,
        const std::vector<uint8_t>& salt,
        SecurityLevel level
    );
    
    static std::vector<uint8_t> generateSalt();
    static std::vector<uint8_t> generateIV(SecurityLevel level);
    
    static void writeHeader(std::ostream& out, const CryptoParams& params);
    static CryptoParams parseHeader(std::istream& in);
    
    static void encryptChunk(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const uint8_t* input, size_t inputLen,
        std::vector<uint8_t>& output,
        std::vector<uint8_t>& tag,
        SecurityLevel level
    );
    
    static void decryptChunk(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const uint8_t* input, size_t inputLen,
        const std::vector<uint8_t>& tag,
        std::vector<uint8_t>& output,
        SecurityLevel level
    );
};

} // namespace encrypt

#endif // ENCRYPT_CRYPTO_H
