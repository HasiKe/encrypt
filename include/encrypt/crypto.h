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
 * @brief Verschlüsselungsstärke von 1 (schnell) bis 5 (maximal sicher)
 */
enum class SecurityLevel {
    LEVEL_1 = 1, // Schnell, aber trotzdem sicher (AES-128)
    LEVEL_2 = 2, // Ausgewogen (AES-256)
    LEVEL_3 = 3, // Erhöhte Sicherheit (AES-256 mit mehr Iterationen)
    LEVEL_4 = 4, // Hohe Sicherheit (AES-256 mit Argon2)
    LEVEL_5 = 5  // Maximale Sicherheit (AES-256 + ChaCha20 mit Argon2id)
};

// Vorwärtsdeklaration
class Crypto;

/**
 * @brief Parameter für die kryptographischen Operationen
 */
struct CryptoParams {
    std::vector<uint8_t> key;        // Abgeleiteter Schlüssel
    std::vector<uint8_t> iv;         // Initialisierungsvektor
    std::vector<uint8_t> salt;       // Salt für die Schlüsselableitung
    std::vector<uint8_t> authTag;    // Authentifizierungs-Tag (für GCM-Modus)
    
    CryptoParams() = default;
    
    // Erzeugt Parameter mit zufälligen Werten für die Verschlüsselung
    static CryptoParams generateForEncryption(SecurityLevel level);
    
    friend class Crypto; // Erlaubt Crypto-Klasse Zugriff auf private Funktionen
};

/**
 * @brief Enthält Funktionen für Ver- und Entschlüsselung
 */
class Crypto {
public:
    /**
     * @brief Verschlüsselt eine Datei mit dem angegebenen Passwort
     * 
     * @param inputFileName Pfad zur Eingabedatei
     * @param outputFileName Pfad zur Ausgabedatei
     * @param password Passwort für die Verschlüsselung
     * @param level Sicherheitsstufe (1-5)
     * @param progressCallback Optional: Callback-Funktion für Fortschrittsaktualisierungen
     * @return true wenn erfolgreich, false bei Fehler
     */
    static bool encryptFile(
        const std::string& inputFileName, 
        const std::string& outputFileName, 
        const std::string& password,
        SecurityLevel level = SecurityLevel::LEVEL_2,
        const std::function<void(float)>& progressCallback = nullptr
    );

    /**
     * @brief Entschlüsselt eine Datei mit dem angegebenen Passwort
     * 
     * @param inputFileName Pfad zur verschlüsselten Datei
     * @param password Passwort für die Entschlüsselung
     * @param outputFileName Optional: Zieldateiname (wenn nicht angegeben, wird der originale verwendet)
     * @param progressCallback Optional: Callback-Funktion für Fortschrittsaktualisierungen
     * @return true wenn erfolgreich, false bei Fehler
     */
    static bool decryptFile(
        const std::string& inputFileName, 
        const std::string& password,
        const std::string& outputFileName = "",
        const std::function<void(float)>& progressCallback = nullptr
    );

    /**
     * @brief Überprüft die Passwortqualität und gibt einen Score zurück
     * 
     * @param password Das zu überprüfende Passwort
     * @return int Score zwischen 0 (sehr schwach) und 100 (sehr stark)
     */
    static int checkPasswordStrength(const std::string& password);

    /**
     * @brief Gibt die letzte Fehlermeldung zurück
     * 
     * @return Die letzte aufgetretene Fehlermeldung
     */
    static std::string getLastError();

    /**
     * @brief Testet die Verschlüsselungsfunktionalität mit einem einfachen String
     * 
     * @param testString Der zu testende String
     * @param level Die zu verwendende Sicherheitsstufe
     * @return true wenn der Test erfolgreich war, false sonst
     */
    static bool testEncryption(const std::string& testString, const std::string& password, SecurityLevel level);

    // Für CryptoParams
    friend CryptoParams CryptoParams::generateForEncryption(SecurityLevel level);

private:
    // Private Hilfsfunktionen für die Kryptographie
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
    
    // Für Sicherheitsstufe 5: Zusätzliche ChaCha20 Verschlüsselung
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
    
    // Hilfsfunktion zum Lesen von Dateien in Chunks
    static bool processFileInChunks(
        const std::string& inputFileName,
        const std::string& outputFileName,
        const std::function<bool(const std::vector<uint8_t>&, std::vector<uint8_t>&)>& processor,
        const std::function<void(float)>& progressCallback
    );
    
    // Fehlerverwaltung
    static thread_local std::string lastError;
};

// Konstanten für die Verschlüsselung
namespace crypto_constants {
    // Dateiformat-Signatur
    constexpr uint8_t FILE_SIGNATURE[4] = {'S', 'E', 'C', 'F'};
    
    // Aktuelle Dateiformat-Version
    constexpr uint8_t FILE_VERSION = 0x01;
    
    // Header-Tag für die Sicherheitsstufe
    constexpr uint8_t HEADER_TAG_SECURITY_LEVEL = 0x01;
    
    // Header-Tag für den Salt
    constexpr uint8_t HEADER_TAG_SALT = 0x02;
    
    // Header-Tag für den IV
    constexpr uint8_t HEADER_TAG_IV = 0x03;
    
    // Header-Tag für den Auth-Tag (GCM)
    constexpr uint8_t HEADER_TAG_AUTH_TAG = 0x04;
    
    // Header-Tag für den Dateinamen
    constexpr uint8_t HEADER_TAG_FILENAME = 0x05;
    
    // Header-Tag für zusätzliche ChaCha20-Parameter
    constexpr uint8_t HEADER_TAG_CHACHA_NONCE = 0x06;
    
    // Schlüssellängen für verschiedene Sicherheitsstufen
    constexpr size_t KEY_SIZE_LEVEL_1 = 16;  // 128 Bit
    constexpr size_t KEY_SIZE_LEVEL_2 = 32;  // 256 Bit
    constexpr size_t KEY_SIZE_LEVEL_3 = 32;  // 256 Bit
    constexpr size_t KEY_SIZE_LEVEL_4 = 32;  // 256 Bit
    constexpr size_t KEY_SIZE_LEVEL_5 = 32;  // 256 Bit
    
    // Größen für Salt und IV
    constexpr size_t SALT_SIZE = 32;
    constexpr size_t IV_SIZE = 16;
    constexpr size_t CHACHA_NONCE_SIZE = 12;
    constexpr size_t GCM_TAG_SIZE = 16;
    
    // Iterationszahlen für PBKDF2 pro Sicherheitsstufe
    constexpr uint32_t PBKDF2_ITERATIONS_LEVEL_1 = 10000;
    constexpr uint32_t PBKDF2_ITERATIONS_LEVEL_2 = 100000;
    constexpr uint32_t PBKDF2_ITERATIONS_LEVEL_3 = 250000;
    
    // Parameter für Argon2 (Stufen 4 und 5)
    constexpr uint32_t ARGON2_TIME_COST_LEVEL_4 = 3;
    constexpr uint32_t ARGON2_MEMORY_COST_LEVEL_4 = 65536; // 64 MB
    constexpr uint32_t ARGON2_PARALLELISM_LEVEL_4 = 4;
    
    constexpr uint32_t ARGON2_TIME_COST_LEVEL_5 = 4;
    constexpr uint32_t ARGON2_MEMORY_COST_LEVEL_5 = 262144; // 256 MB
    constexpr uint32_t ARGON2_PARALLELISM_LEVEL_5 = 8;
}

} // namespace encrypt

#endif // ENCRYPT_CRYPTO_H