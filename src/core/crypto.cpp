#include "encrypt/crypto.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <array>
#include <algorithm>
#include <random>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <regex>
#include <filesystem>
#include <set>

// OpenSSL-Header
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

// Für kompilierte Versionen ohne Argon2-Support
#ifdef SIMULATED_ARGON2
// Konstanten für Argon2 Mock
#define ARGON2_OK 0

// Einfache Simulation von Argon2 für Testzwecke
int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                     const uint32_t parallelism, const void *pwd,
                     const size_t pwdlen, const void *salt,
                     const size_t saltlen, void *hash, const size_t hashlen) {
    // ACHTUNG: Das ist nur eine Simulation für Testzwecke!
    // In einer echten Anwendung sollte die tatsächliche Argon2-Bibliothek verwendet werden
    
    // Verwende stattdessen PBKDF2 mit sehr vielen Iterationen
    PKCS5_PBKDF2_HMAC(
        static_cast<const char*>(pwd), static_cast<int>(pwdlen),
        static_cast<const unsigned char*>(salt), static_cast<int>(saltlen),
        100000 + t_cost * 10000, // Simuliere höhere Kosten
        EVP_sha512(),
        static_cast<int>(hashlen),
        static_cast<unsigned char*>(hash)
    );
    
    return ARGON2_OK;
}

const char* argon2_error_message(int) {
    return "Simulated Argon2";
}
#else
// Argon2-Header
#include <argon2.h>
#endif

// Libsodium, falls verfügbar
#ifdef USE_LIBSODIUM
#include <sodium.h>
#endif

namespace encrypt {

using namespace crypto_constants;

// Static Variablen initialisieren
thread_local std::string Crypto::lastError;

// Hilfsfunktion für OpenSSL-Fehler
std::string getOpenSSLError() {
    char errbuf[256];
    unsigned long err = ERR_get_error();
    if (err == 0) {
        return "Kein OpenSSL-Fehler";
    }
    ERR_error_string_n(err, errbuf, sizeof(errbuf));
    return errbuf;
}

// Zufällige Bytes generieren mit OpenSSL
std::vector<uint8_t> Crypto::generateRandomBytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    
    int result = RAND_bytes(bytes.data(), static_cast<int>(length));
    if (result != 1) {
        lastError = "Fehler beim Generieren von Zufallszahlen: " + getOpenSSLError();
        return {};
    }
    
    return bytes;
}

// Erzeugt Crypto-Parameter für die Verschlüsselung
CryptoParams CryptoParams::generateForEncryption(SecurityLevel level) {
    CryptoParams params;
    
    // Größe des Salts und IV sind konstant
    params.salt = Crypto::generateRandomBytes(SALT_SIZE);
    params.iv = Crypto::generateRandomBytes(IV_SIZE);
    
    // Für Stufe 5: Erstelle zusätzliche ChaCha20-Parameter
    if (level == SecurityLevel::LEVEL_5) {
        // ChaCha20 benötigt einen zusätzlichen Nonce
        std::vector<uint8_t> chachaNonce = Crypto::generateRandomBytes(CHACHA_NONCE_SIZE);
        params.iv.insert(params.iv.end(), chachaNonce.begin(), chachaNonce.end());
    }
    
    return params;
}

// Schlüsselableitungsfunktion
CryptoParams Crypto::deriveKeyFromPassword(
    const std::string& password, 
    const std::vector<uint8_t>& salt,
    SecurityLevel level
) {
    if (password.empty()) {
        lastError = "Passwort darf nicht leer sein";
        return {};
    }
    
    CryptoParams params;
    params.salt = salt;
    
    // Bestimme Schlüsselgröße basierend auf Sicherheitsstufe
    size_t keySize;
    switch (level) {
        case SecurityLevel::LEVEL_1: keySize = KEY_SIZE_LEVEL_1; break;
        default: keySize = KEY_SIZE_LEVEL_2; break; // Level 2-5 verwenden AES-256
    }
    
    // Reserviere Speicher für den Schlüssel
    params.key.resize(keySize);
    
    // Je nach Sicherheitsstufe unterschiedliche Schlüsselableitungsverfahren
    int result = 0;
    
    if (level == SecurityLevel::LEVEL_1 || level == SecurityLevel::LEVEL_2 || level == SecurityLevel::LEVEL_3) {
        // Verwende PBKDF2 für Stufen 1-3
        uint32_t iterations;
        switch (level) {
            case SecurityLevel::LEVEL_1: iterations = PBKDF2_ITERATIONS_LEVEL_1; break;
            case SecurityLevel::LEVEL_2: iterations = PBKDF2_ITERATIONS_LEVEL_2; break;
            case SecurityLevel::LEVEL_3: iterations = PBKDF2_ITERATIONS_LEVEL_3; break;
            default: iterations = PBKDF2_ITERATIONS_LEVEL_2; break;
        }
        
        result = PKCS5_PBKDF2_HMAC(
            password.c_str(), static_cast<int>(password.length()),
            salt.data(), static_cast<int>(salt.size()),
            iterations,
            EVP_sha512(), // Verwende SHA-512 für bessere Sicherheit
            static_cast<int>(keySize),
            params.key.data()
        );
        
        if (result != 1) {
            lastError = "Fehler bei der Schlüsselableitung (PBKDF2): " + getOpenSSLError();
            return {};
        }
    } else {
        // Verwende Argon2id für Stufen 4-5 (speicher- und rechenintensiv)
        uint32_t timeCost, memoryCost, parallelism;
        
        if (level == SecurityLevel::LEVEL_4) {
            timeCost = ARGON2_TIME_COST_LEVEL_4;
            memoryCost = ARGON2_MEMORY_COST_LEVEL_4;
            parallelism = ARGON2_PARALLELISM_LEVEL_4;
        } else {
            timeCost = ARGON2_TIME_COST_LEVEL_5;
            memoryCost = ARGON2_MEMORY_COST_LEVEL_5;
            parallelism = ARGON2_PARALLELISM_LEVEL_5;
        }
        
        // Verwende Argon2id mit den konfigurierten Parametern
        result = argon2id_hash_raw(
            timeCost, memoryCost, parallelism,
            password.c_str(), password.length(),
            salt.data(), salt.size(),
            params.key.data(), keySize
        );
        
        if (result != ARGON2_OK) {
            lastError = "Fehler bei der Schlüsselableitung (Argon2): ";
#ifndef SIMULATED_ARGON2
            lastError += argon2_error_message(result);
#else
            lastError += "Fehler " + std::to_string(result);
#endif
            return {};
        }
    }
    
    // Wenn Level 5, dann mache den Schlüssel doppelt so groß für ChaCha20
    if (level == SecurityLevel::LEVEL_5) {
        size_t originalKeySize = params.key.size();
        params.key.resize(originalKeySize * 2);
        
        // Berechne den zweiten Teil des Schlüssels mit HMAC-SHA512
        uint8_t hmac[SHA512_DIGEST_LENGTH];
        unsigned int hmacLen;
        
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx) {
            lastError = "Fehler beim Erstellen des HMAC-Kontexts";
            return {};
        }
        
        // Initialisiere HMAC mit dem ersten Schlüsselteil
        if (!HMAC_Init_ex(ctx, params.key.data(), static_cast<int>(originalKeySize), EVP_sha512(), nullptr)) {
            HMAC_CTX_free(ctx);
            lastError = "Fehler beim Initialisieren des HMAC: " + getOpenSSLError();
            return {};
        }
        
        // Update HMAC mit Salt und Passwort
        if (!HMAC_Update(ctx, salt.data(), salt.size()) ||
            !HMAC_Update(ctx, reinterpret_cast<const uint8_t*>(password.c_str()), password.length())) {
            HMAC_CTX_free(ctx);
            lastError = "Fehler beim Aktualisieren des HMAC: " + getOpenSSLError();
            return {};
        }
        
        // Finalisiere HMAC
        if (!HMAC_Final(ctx, hmac, &hmacLen)) {
            HMAC_CTX_free(ctx);
            lastError = "Fehler beim Finalisieren des HMAC: " + getOpenSSLError();
            return {};
        }
        
        HMAC_CTX_free(ctx);
        
        // Kopiere HMAC-Ausgabe in den zweiten Teil des Schlüssels
        std::copy_n(hmac, originalKeySize, params.key.data() + originalKeySize);
    }
    
    return params;
}

// AES-Verschlüsselung
bool Crypto::encryptAES(
    const std::vector<uint8_t>& input, 
    std::vector<uint8_t>& output,
    const CryptoParams& params,
    SecurityLevel level
) {
    std::cerr << "DEBUG: encryptAES called with input size: " << input.size() << std::endl;
    
    // Bestimme Schlüsselgröße und Cipher
    const EVP_CIPHER* cipher;
    switch (level) {
        case SecurityLevel::LEVEL_1:
            cipher = EVP_aes_128_gcm(); // AES-128-GCM
            break;
        default:
            cipher = EVP_aes_256_gcm(); // AES-256-GCM (Authenticated Encryption)
            break;
    }
    
    std::cerr << "DEBUG: Using key size: " << params.key.size() << " bytes" << std::endl;
    std::cerr << "DEBUG: Using IV size: " << params.iv.size() << " bytes" << std::endl;
    
    // Erstelle Verschlüsselungskontext
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        lastError = "Fehler beim Erstellen des Verschlüsselungskontexts";
        return false;
    }
    
    // Initialisiere Verschlüsselung
    int result = EVP_EncryptInit_ex(
        ctx, 
        cipher, 
        nullptr, 
        params.key.data(), 
        params.iv.data()
    );
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim Initialisieren der Verschlüsselung: " + getOpenSSLError();
        return false;
    }
    
    // Reserviere Ausgabepuffer (kann größer sein als Eingabe wegen Padding)
    output.resize(input.size() + EVP_CIPHER_block_size(cipher));
    
    // Verschlüssele Daten
    int outlen1 = 0;
    result = EVP_EncryptUpdate(
        ctx, 
        output.data(), 
        &outlen1, 
        input.data(), 
        static_cast<int>(input.size())
    );
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim Verschlüsseln: " + getOpenSSLError();
        return false;
    }
    
    // Finalisiere Verschlüsselung
    int outlen2 = 0;
    result = EVP_EncryptFinal_ex(ctx, output.data() + outlen1, &outlen2);
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim Finalisieren der Verschlüsselung: " + getOpenSSLError();
        return false;
    }
    
    // Hole den GCM-Tag (für Authentizitätsprüfung)
    std::vector<uint8_t> tag(GCM_TAG_SIZE);
    result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data());
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim Abrufen des Authentication-Tags: " + getOpenSSLError();
        return false;
    }
    
    std::cerr << "DEBUG: Auth tag size: " << tag.size() << " bytes" << std::endl;
    
    // Passe Größe der Ausgabe an
    output.resize(outlen1 + outlen2);
    std::cerr << "DEBUG: Encrypted output size: " << output.size() << " bytes" << std::endl;
    
    // Speichere das Authentication-Tag für die Verifikation
    const_cast<CryptoParams&>(params).authTag = std::move(tag);
    
    // Bereinige Ressourcen
    EVP_CIPHER_CTX_free(ctx);
    
    return true;
}

// AES-Entschlüsselung
bool Crypto::decryptAES(
    const std::vector<uint8_t>& input, 
    std::vector<uint8_t>& output,
    const CryptoParams& params,
    SecurityLevel level
) {
    std::cerr << "DEBUG: decryptAES called with input size: " << input.size() << std::endl;
    std::cerr << "DEBUG: Auth tag size: " << params.authTag.size() << " bytes" << std::endl;
    
    // Bestimme Cipher basierend auf Sicherheitsstufe
    const EVP_CIPHER* cipher;
    switch (level) {
        case SecurityLevel::LEVEL_1:
            cipher = EVP_aes_128_gcm();
            break;
        default:
            cipher = EVP_aes_256_gcm();
            break;
    }
    
    // Erstelle Entschlüsselungskontext
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        lastError = "Fehler beim Erstellen des Entschlüsselungskontexts";
        return false;
    }
    
    // Initialisiere Entschlüsselung
    int result = EVP_DecryptInit_ex(
        ctx, 
        cipher, 
        nullptr, 
        params.key.data(), 
        params.iv.data()
    );
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim Initialisieren der Entschlüsselung: " + getOpenSSLError();
        return false;
    }
    
    // Setze GCM-Tag für Authentizitätsprüfung
    if (params.authTag.empty()) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler: Authentication-Tag fehlt";
        return false;
    }
    
    result = EVP_CIPHER_CTX_ctrl(
        ctx, 
        EVP_CTRL_GCM_SET_TAG, 
        static_cast<int>(params.authTag.size()), 
        const_cast<uint8_t*>(params.authTag.data())
    );
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim Setzen des Authentication-Tags: " + getOpenSSLError();
        return false;
    }
    
    // Reserviere Ausgabepuffer
    output.resize(input.size());
    
    // Entschlüssele Daten
    int outlen1 = 0;
    result = EVP_DecryptUpdate(
        ctx, 
        output.data(), 
        &outlen1, 
        input.data(), 
        static_cast<int>(input.size())
    );
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim Entschlüsseln: " + getOpenSSLError();
        return false;
    }
    
    // Finalisiere Entschlüsselung
    int outlen2 = 0;
    result = EVP_DecryptFinal_ex(ctx, output.data() + outlen1, &outlen2);
    
    // GCM wird den Tag überprüfen und bei Manipulation fehlschlagen
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim Finalisieren der Entschlüsselung oder Authentizitätsprüfung fehlgeschlagen: " 
                   + getOpenSSLError();
        return false;
    }
    
    // Passe Größe der Ausgabe an
    output.resize(outlen1 + outlen2);
    std::cerr << "DEBUG: Decrypted output size: " << output.size() << " bytes" << std::endl;
    
    // Bereinige Ressourcen
    EVP_CIPHER_CTX_free(ctx);
    
    return true;
}

// ChaCha20-Verschlüsselung für Sicherheitsstufe 5
bool Crypto::encryptChaCha20(
    const std::vector<uint8_t>& input, 
    std::vector<uint8_t>& output,
    const CryptoParams& params
) {
#ifdef USE_LIBSODIUM
    // libsodium-Version
    if (sodium_init() < 0) {
        lastError = "Fehler beim Initialisieren von libsodium";
        return false;
    }
    
    output.resize(input.size());
    
    // Parameter extrahieren
    const uint8_t* key = params.key.data() + KEY_SIZE_LEVEL_5; // Zweiter Teil des Schlüssels
    const uint8_t* nonce = params.iv.data() + IV_SIZE;         // ChaCha20-Nonce ist nach dem IV
    
    // libsodium ChaCha20
    crypto_stream_chacha20_xor(
        output.data(),
        input.data(),
        input.size(),
        nonce,
        key
    );
    
    return true;
#else
    // OpenSSL-Version
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        lastError = "Fehler beim Erstellen des ChaCha20-Kontexts";
        return false;
    }
    
    // Parameter extrahieren
    const uint8_t* key = params.key.data() + KEY_SIZE_LEVEL_5; // Zweiter Teil des Schlüssels
    const uint8_t* nonce = params.iv.data() + IV_SIZE;         // ChaCha20-Nonce ist nach dem IV
    
    int result = EVP_EncryptInit_ex(
        ctx, 
        EVP_chacha20(), 
        nullptr, 
        key, 
        nonce
    );
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim Initialisieren von ChaCha20: " + getOpenSSLError();
        return false;
    }
    
    // Reserviere Ausgabepuffer
    output.resize(input.size() + 16); // Extra Platz für mögliches Padding
    
    // Verschlüssele Daten
    int outlen1 = 0;
    result = EVP_EncryptUpdate(
        ctx, 
        output.data(), 
        &outlen1, 
        input.data(), 
        static_cast<int>(input.size())
    );
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim ChaCha20-Verschlüsseln: " + getOpenSSLError();
        return false;
    }
    
    // Finalisiere Verschlüsselung
    int outlen2 = 0;
    result = EVP_EncryptFinal_ex(ctx, output.data() + outlen1, &outlen2);
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim Finalisieren der ChaCha20-Verschlüsselung: " + getOpenSSLError();
        return false;
    }
    
    // Passe Größe der Ausgabe an
    output.resize(outlen1 + outlen2);
    
    // Bereinige Ressourcen
    EVP_CIPHER_CTX_free(ctx);
    
    return true;
#endif
}

// ChaCha20-Entschlüsselung für Sicherheitsstufe 5
bool Crypto::decryptChaCha20(
    const std::vector<uint8_t>& input, 
    std::vector<uint8_t>& output,
    const CryptoParams& params
) {
#ifdef USE_LIBSODIUM
    // libsodium-Version (bei symmetrischer Verschlüsselung ist Entschlüsselung gleich)
    return encryptChaCha20(input, output, params);
#else
    // OpenSSL-Version
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        lastError = "Fehler beim Erstellen des ChaCha20-Entschlüsselungskontexts";
        return false;
    }
    
    // Parameter extrahieren
    const uint8_t* key = params.key.data() + KEY_SIZE_LEVEL_5; // Zweiter Teil des Schlüssels
    const uint8_t* nonce = params.iv.data() + IV_SIZE;         // ChaCha20-Nonce ist nach dem IV
    
    int result = EVP_DecryptInit_ex(
        ctx, 
        EVP_chacha20(), 
        nullptr, 
        key, 
        nonce
    );
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim Initialisieren der ChaCha20-Entschlüsselung: " + getOpenSSLError();
        return false;
    }
    
    // Reserviere Ausgabepuffer
    output.resize(input.size());
    
    // Entschlüssele Daten
    int outlen1 = 0;
    result = EVP_DecryptUpdate(
        ctx, 
        output.data(), 
        &outlen1, 
        input.data(), 
        static_cast<int>(input.size())
    );
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim ChaCha20-Entschlüsseln: " + getOpenSSLError();
        return false;
    }
    
    // Finalisiere Entschlüsselung
    int outlen2 = 0;
    result = EVP_DecryptFinal_ex(ctx, output.data() + outlen1, &outlen2);
    
    if (result != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lastError = "Fehler beim Finalisieren der ChaCha20-Entschlüsselung: " + getOpenSSLError();
        return false;
    }
    
    // Passe Größe der Ausgabe an
    output.resize(outlen1 + outlen2);
    
    // Bereinige Ressourcen
    EVP_CIPHER_CTX_free(ctx);
    
    return true;
#endif
}

// Verarbeitung einer Datei in Chunks
bool Crypto::processFileInChunks(
    const std::string& inputFileName,
    const std::string& outputFileName,
    const std::function<bool(const std::vector<uint8_t>&, std::vector<uint8_t>&)>& processor,
    const std::function<void(float)>& progressCallback
) {
    // Öffne Eingabedatei
    std::ifstream inputFile(inputFileName, std::ios::binary);
    if (!inputFile) {
        lastError = "Fehler beim Öffnen der Eingabedatei: " + inputFileName;
        return false;
    }
    
    // Öffne Ausgabedatei
    std::ofstream outputFile(outputFileName, std::ios::binary);
    if (!outputFile) {
        lastError = "Fehler beim Erstellen der Ausgabedatei: " + outputFileName;
        return false;
    }
    
    // Bestimme Dateigröße für Fortschrittsberechnung
    inputFile.seekg(0, std::ios::end);
    std::streamsize totalSize = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);
    
    // Puffergröße für Chunks (64 KB)
    constexpr size_t bufferSize = 64 * 1024;
    std::vector<uint8_t> inputBuffer(bufferSize);
    std::vector<uint8_t> outputBuffer;
    
    // Verarbeite Datei in Chunks
    std::streamsize processedBytes = 0;
    while (inputFile) {
        // Lese einen Chunk
        inputFile.read(reinterpret_cast<char*>(inputBuffer.data()), bufferSize);
        std::streamsize bytesRead = inputFile.gcount();
        
        if (bytesRead <= 0) {
            break;
        }
        
        // Passe Puffergröße an tatsächlich gelesene Bytes an
        inputBuffer.resize(static_cast<size_t>(bytesRead));
        
        // Verarbeite Chunk
        if (!processor(inputBuffer, outputBuffer)) {
            return false;
        }
        
        // Schreibe verarbeitete Daten
        outputFile.write(reinterpret_cast<const char*>(outputBuffer.data()), outputBuffer.size());
        
        if (!outputFile) {
            lastError = "Fehler beim Schreiben in die Ausgabedatei";
            return false;
        }
        
        // Aktualisiere Fortschritt
        processedBytes += bytesRead;
        if (progressCallback && totalSize > 0) {
            progressCallback(static_cast<float>(processedBytes) / totalSize);
        }
        
        // Setze Puffer für nächsten Chunk zurück
        inputBuffer.resize(bufferSize);
    }
    
    // Abschließender Fortschritt
    if (progressCallback) {
        progressCallback(1.0f);
    }
    
    return true;
}

// Passwort-Stärke überprüfen
int Crypto::checkPasswordStrength(const std::string& password) {
    // Mindestanforderungen
    if (password.length() < 8) {
        return 0; // Zu kurz
    }
    
    int score = 0;
    
    // Länge (0-25 Punkte)
    score += std::min(25, static_cast<int>(password.length()) * 2);
    
    // Zeichenvielfalt (0-35 Punkte)
    bool hasLower = std::regex_search(password, std::regex("[a-z]"));
    bool hasUpper = std::regex_search(password, std::regex("[A-Z]"));
    bool hasDigit = std::regex_search(password, std::regex("[0-9]"));
    bool hasSpecial = std::regex_search(password, std::regex("[^a-zA-Z0-9]"));
    
    if (hasLower) score += 10;
    if (hasUpper) score += 10;
    if (hasDigit) score += 10;
    if (hasSpecial) score += 15;
    
    // Entropie und Muster (0-40 Punkte)
    std::set<char> uniqueChars(password.begin(), password.end());
    
    // Prozentsatz eindeutiger Zeichen
    double uniqueRatio = static_cast<double>(uniqueChars.size()) / password.length();
    score += static_cast<int>(uniqueRatio * 15);
    
    // Prüfe auf Sequenzen und Wiederholungen
    bool hasRepetition = std::regex_search(password, std::regex("(.)\\1{2,}"));
    bool hasSequence = std::regex_search(password, std::regex("(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)"));
    
    if (hasRepetition) score -= 10;
    if (hasSequence) score -= 10;
    
    // Begrenzen auf 0-100
    return std::max(0, std::min(100, score));
}

// Datei verschlüsseln
bool Crypto::encryptFile(
    const std::string& inputFileName, 
    const std::string& outputFileName, 
    const std::string& password,
    SecurityLevel level,
    const std::function<void(float)>& progressCallback
) {
    std::cerr << "DEBUG: Starting encryption of file: " << inputFileName << std::endl;
    std::cerr << "DEBUG: Output file: " << outputFileName << std::endl;
    std::cerr << "DEBUG: Security level: " << static_cast<int>(level) << std::endl;
    
    try {
        // Überprüfe Passwort-Stärke
        std::cerr << "DEBUG: Checking password strength" << std::endl;
        int passwordStrength = checkPasswordStrength(password);
        if (passwordStrength < 30) {
            lastError = "Schwaches Passwort (Stärke: " + std::to_string(passwordStrength) + "/100). "
                        "Ein stärkeres Passwort wird empfohlen.";
            // Wir warnen nur, brechen aber nicht ab
        }
        
        // Überprüfe, ob die Eingabedatei existiert
        std::cerr << "DEBUG: Checking if input file exists" << std::endl;
        std::ifstream checkFile(inputFileName, std::ios::binary);
        if (!checkFile) {
            lastError = "Eingabedatei existiert nicht oder ist nicht lesbar: " + inputFileName;
            return false;
        }
        checkFile.close();
        
        // Erzeuge Parameter für die Verschlüsselung
        std::cerr << "DEBUG: Generating encryption parameters" << std::endl;
        CryptoParams params = CryptoParams::generateForEncryption(level);
        
        // Leite Schlüssel vom Passwort ab
        std::cerr << "DEBUG: Deriving key from password" << std::endl;
        params = deriveKeyFromPassword(password, params.salt, level);
        if (params.key.empty()) {
            // Fehlermeldung wurde bereits in deriveKeyFromPassword gesetzt
            std::cerr << "DEBUG: Key derivation failed: " << lastError << std::endl;
            return false;
        }
        
        // Öffne die Ausgabedatei
        std::cerr << "DEBUG: Opening output file" << std::endl;
        std::ofstream outputFile(outputFileName, std::ios::binary);
        if (!outputFile) {
            lastError = "Fehler beim Erstellen der Ausgabedatei: " + outputFileName;
            return false;
        }
        
        // Schreibe Header
        std::cerr << "DEBUG: Writing file header" << std::endl;
        try {
            // 1. Signatur
            std::cerr << "DEBUG: Writing file signature" << std::endl;
            outputFile.write(reinterpret_cast<const char*>(FILE_SIGNATURE), 4);
            
            // 2. Version
            std::cerr << "DEBUG: Writing file version" << std::endl;
            outputFile.put(FILE_VERSION);
            
            // 3. Sicherheitsstufe
            std::cerr << "DEBUG: Writing security level" << std::endl;
            outputFile.put(HEADER_TAG_SECURITY_LEVEL);
            outputFile.put(static_cast<char>(level));
            
            // 4. Salt
            std::cerr << "DEBUG: Writing salt (size: " << params.salt.size() << ")" << std::endl;
            outputFile.put(HEADER_TAG_SALT);
            outputFile.put(static_cast<char>(params.salt.size()));
            outputFile.write(reinterpret_cast<const char*>(params.salt.data()), params.salt.size());
            
            // 5. IV
            size_t ivSize = (level == SecurityLevel::LEVEL_5) ? IV_SIZE + CHACHA_NONCE_SIZE : IV_SIZE;
            std::cerr << "DEBUG: Writing IV (size: " << ivSize << ")" << std::endl;
            outputFile.put(HEADER_TAG_IV);
            outputFile.put(static_cast<char>(ivSize));
            outputFile.write(reinterpret_cast<const char*>(params.iv.data()), ivSize);
        } catch (const std::exception& e) {
            std::cerr << "DEBUG: Exception during header writing: " << e.what() << std::endl;
            lastError = "Fehler beim Schreiben des Headers: ";
            lastError += e.what();
            return false;
        }
        
        // 6. Verschlüsselter Dateiname
        std::cerr << "DEBUG: Encrypting filename" << std::endl;
        
        try {
            // Get just the basename from the path
            std::cerr << "DEBUG: Input filename: " << inputFileName << std::endl;
            
            // Extract filename without using filesystem (for simplicity)
            std::string fileName = inputFileName;
            size_t lastSlash = fileName.find_last_of("/\\");
            if (lastSlash != std::string::npos) {
                fileName = fileName.substr(lastSlash + 1);
            }
            std::cerr << "DEBUG: Extracted filename: " << fileName << std::endl;
            
            // Convert filename to bytes and encrypt it
            std::vector<uint8_t> fileNameBytes(fileName.begin(), fileName.end());
            std::vector<uint8_t> encryptedFileName;
            
            if (!encryptAES(fileNameBytes, encryptedFileName, params, level)) {
                std::cerr << "DEBUG: Failed to encrypt filename: " << lastError << std::endl;
                return false;
            }
            
            // Write the encrypted filename to the header
            std::cerr << "DEBUG: Writing filename header" << std::endl;
            outputFile.put(HEADER_TAG_FILENAME);
            uint16_t fileNameSize = static_cast<uint16_t>(encryptedFileName.size());
            outputFile.write(reinterpret_cast<const char*>(&fileNameSize), sizeof(fileNameSize));
            outputFile.write(reinterpret_cast<const char*>(encryptedFileName.data()), encryptedFileName.size());
            
            // Write the GCM authentication tag
            std::cerr << "DEBUG: Writing auth tag" << std::endl;
            outputFile.put(HEADER_TAG_AUTH_TAG);
            outputFile.put(static_cast<char>(params.authTag.size()));
            outputFile.write(reinterpret_cast<const char*>(params.authTag.data()), params.authTag.size());
        } catch (const std::exception& e) {
            std::cerr << "DEBUG: Exception during filename processing: " << e.what() << std::endl;
            lastError = "Fehler bei der Verarbeitung des Dateinamens: ";
            lastError += e.what();
            return false;
        }
        
        try {
            // Schreibe einen Null-Terminator für das Ende des Headers
            std::cerr << "DEBUG: Writing null terminator" << std::endl;
            outputFile.put('\0');
            
            std::cerr << "DEBUG: Processing file in chunks" << std::endl;
            
            // Verarbeite die Datei in Chunks
            auto processor = [&params, level](const std::vector<uint8_t>& input, std::vector<uint8_t>& output) -> bool {
                std::cerr << "DEBUG: Processing chunk of size " << input.size() << std::endl;
                
                // Verschlüssele mit AES
                if (!Crypto::encryptAES(input, output, params, level)) {
                    std::cerr << "DEBUG: AES encryption failed: " << Crypto::getLastError() << std::endl;
                    return false;
                }
                
                // Für Sicherheitsstufe 5: Zusätzliche ChaCha20-Verschlüsselung
                if (level == SecurityLevel::LEVEL_5) {
                    std::vector<uint8_t> chacha20Output;
                    if (!Crypto::encryptChaCha20(output, chacha20Output, params)) {
                        std::cerr << "DEBUG: ChaCha20 encryption failed: " << Crypto::getLastError() << std::endl;
                        return false;
                    }
                    output = std::move(chacha20Output);
                }
                
                // Füge den Auth-Tag hinzu
                std::vector<uint8_t> withTag = output;
                withTag.insert(withTag.end(), params.authTag.begin(), params.authTag.end());
                output = std::move(withTag);
                
                return true;
            };
            
            return processFileInChunks(inputFileName, outputFileName, processor, progressCallback);
        } catch (const std::exception& e) {
            std::cerr << "DEBUG: Exception during file processing: " << e.what() << std::endl;
            lastError = "Fehler bei der Verarbeitung der Datei: ";
            lastError += e.what();
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "DEBUG EXCEPTION: " << e.what() << std::endl;
        throw;
    } catch (...) {
        std::cerr << "DEBUG EXCEPTION: Unknown exception" << std::endl;
        throw;
    }
}

// Datei entschlüsseln
bool Crypto::decryptFile(
    const std::string& inputFileName, 
    const std::string& password,
    const std::string& outputFileName,
    const std::function<void(float)>& progressCallback
) {
    // Öffne die Eingabedatei
    std::ifstream inputFile(inputFileName, std::ios::binary);
    if (!inputFile) {
        lastError = "Fehler beim Öffnen der verschlüsselten Datei: " + inputFileName;
        return false;
    }
    
    // Header lesen
    // 1. Signatur überprüfen
    char signatureBuffer[4];
    inputFile.read(signatureBuffer, 4);
    if (!inputFile || memcmp(signatureBuffer, FILE_SIGNATURE, 4) != 0) {
        lastError = "Ungültiges Dateiformat oder keine verschlüsselte Datei";
        return false;
    }
    
    // 2. Version überprüfen
    char version;
    inputFile.get(version);
    if (!inputFile || version != FILE_VERSION) {
        lastError = "Nicht unterstützte Dateiversion";
        return false;
    }
    
    // Header-Daten
    SecurityLevel level = SecurityLevel::LEVEL_2; // Standardwert
    std::vector<uint8_t> salt;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> encryptedFileName;
    std::vector<uint8_t> authTag;
    
    // 3. Header-Tags lesen
    while (inputFile) {
        char tag;
        inputFile.get(tag);
        
        if (!inputFile) {
            lastError = "Fehler beim Lesen des Dateiheaders";
            return false;
        }
        
        // Ende des Headers
        if (tag == '\0') {
            break;
        }
        
        switch (tag) {
            case HEADER_TAG_SECURITY_LEVEL: {
                char levelChar;
                inputFile.get(levelChar);
                if (!inputFile) {
                    lastError = "Fehler beim Lesen der Sicherheitsstufe";
                    return false;
                }
                level = static_cast<SecurityLevel>(levelChar);
                break;
            }
            
            case HEADER_TAG_SALT: {
                char saltSize;
                inputFile.get(saltSize);
                if (!inputFile) {
                    lastError = "Fehler beim Lesen der Salt-Größe";
                    return false;
                }
                
                salt.resize(saltSize);
                inputFile.read(reinterpret_cast<char*>(salt.data()), saltSize);
                if (!inputFile) {
                    lastError = "Fehler beim Lesen des Salts";
                    return false;
                }
                break;
            }
            
            case HEADER_TAG_IV: {
                char ivSize;
                inputFile.get(ivSize);
                if (!inputFile) {
                    lastError = "Fehler beim Lesen der IV-Größe";
                    return false;
                }
                
                iv.resize(ivSize);
                inputFile.read(reinterpret_cast<char*>(iv.data()), ivSize);
                if (!inputFile) {
                    lastError = "Fehler beim Lesen des IV";
                    return false;
                }
                break;
            }
            
            case HEADER_TAG_FILENAME: {
                uint16_t fileNameSize;
                inputFile.read(reinterpret_cast<char*>(&fileNameSize), sizeof(fileNameSize));
                if (!inputFile) {
                    lastError = "Fehler beim Lesen der Dateinamensgröße";
                    return false;
                }
                
                encryptedFileName.resize(fileNameSize);
                inputFile.read(reinterpret_cast<char*>(encryptedFileName.data()), fileNameSize);
                if (!inputFile) {
                    lastError = "Fehler beim Lesen des verschlüsselten Dateinamens";
                    return false;
                }
                break;
            }
            
            case HEADER_TAG_AUTH_TAG: {
                char authTagSize;
                inputFile.get(authTagSize);
                if (!inputFile) {
                    lastError = "Fehler beim Lesen der Auth-Tag-Größe";
                    return false;
                }
                
                authTag.resize(authTagSize);
                inputFile.read(reinterpret_cast<char*>(authTag.data()), authTagSize);
                if (!inputFile) {
                    lastError = "Fehler beim Lesen des Auth-Tags";
                    return false;
                }
                break;
            }
            
            default:
                // Unbekanntes Tag überspringen
                char unknownSize;
                inputFile.get(unknownSize);
                if (!inputFile) {
                    lastError = "Fehler beim Lesen eines unbekannten Header-Tags";
                    return false;
                }
                
                inputFile.seekg(unknownSize, std::ios::cur);
                if (!inputFile) {
                    lastError = "Fehler beim Überspringen eines unbekannten Header-Tags";
                    return false;
                }
                break;
        }
    }
    
    // Überprüfe, ob alle notwendigen Header-Daten vorhanden sind
    if (salt.empty() || iv.empty()) {
        lastError = "Fehlende kryptographische Parameter im Header";
        return false;
    }
    
    // Leite Schlüssel vom Passwort ab
    CryptoParams params;
    params.salt = salt;
    params.iv = iv;
    params.authTag = authTag;
    
    params = deriveKeyFromPassword(password, salt, level);
    if (params.key.empty()) {
        // Fehlermeldung wurde bereits in deriveKeyFromPassword gesetzt
        return false;
    }
    
    // Auth-Tag für Dateinamen zurück in Parameter setzen
    params.authTag = authTag;
    
    // Dateinamen entschlüsseln
    std::vector<uint8_t> decryptedFileNameBytes;
    if (!decryptAES(encryptedFileName, decryptedFileNameBytes, params, level)) {
        lastError = "Fehler beim Entschlüsseln des Dateinamens. Falsches Passwort?";
        return false;
    }
    
    std::string decryptedFileName(decryptedFileNameBytes.begin(), decryptedFileNameBytes.end());
    
    // Bestimme den Ausgabedateinamen
    std::string finalOutputFileName;
    if (!outputFileName.empty()) {
        finalOutputFileName = outputFileName;
    } else {
        finalOutputFileName = decryptedFileName;
        
        // Falls der entschlüsselte Dateiname einen Pfad enthält, nur den Dateinamen verwenden
        size_t lastSlash = finalOutputFileName.find_last_of("/\\");
        if (lastSlash != std::string::npos) {
            finalOutputFileName = finalOutputFileName.substr(lastSlash + 1);
        }
        
        // Wenn die Datei bereits existiert, füge "(Wiederhergestellt)" hinzu
        if (std::filesystem::exists(finalOutputFileName)) {
            size_t dotPos = finalOutputFileName.find_last_of('.');
            if (dotPos != std::string::npos) {
                finalOutputFileName.insert(dotPos, " (Wiederhergestellt)");
            } else {
                finalOutputFileName += " (Wiederhergestellt)";
            }
        }
    }
    
    // Aktuelle Position merken (Ende des Headers)
    std::streampos dataStart = inputFile.tellg();
    
    // Dateigröße ermitteln
    inputFile.seekg(0, std::ios::end);
    std::streamsize totalSize = inputFile.tellg() - dataStart;
    inputFile.seekg(dataStart, std::ios::beg);
    
    // Öffne die Ausgabedatei
    std::ofstream outputFile(finalOutputFileName, std::ios::binary);
    if (!outputFile) {
        lastError = "Fehler beim Erstellen der Ausgabedatei: " + finalOutputFileName;
        return false;
    }
    
    // Puffergröße für Chunks (64 KB + Platz für Auth-Tag)
    const size_t chunkSize = 64 * 1024;
    const size_t bufferSize = chunkSize + GCM_TAG_SIZE;
    std::vector<uint8_t> buffer(bufferSize);
    
    // Verarbeite die Datei in Chunks
    std::streamsize processedBytes = 0;
    while (inputFile) {
        // Lese einen Chunk
        inputFile.read(reinterpret_cast<char*>(buffer.data()), bufferSize);
        std::streamsize bytesRead = inputFile.gcount();
        
        if (bytesRead <= 0) {
            break;
        }
        
        // Passe die Puffergröße an
        buffer.resize(static_cast<size_t>(bytesRead));
        
        // Extrahiere den Auth-Tag (am Ende des Chunks)
        size_t dataSize = buffer.size();
        if (dataSize >= GCM_TAG_SIZE) {
            dataSize -= GCM_TAG_SIZE;
            params.authTag.assign(buffer.begin() + dataSize, buffer.end());
            buffer.resize(dataSize);
        } else {
            lastError = "Ungültiges Datenformat oder beschädigte Datei";
            return false;
        }
        
        // Entschlüssele den Chunk
        std::vector<uint8_t> decryptedData;
        
        // Für Sicherheitsstufe 5: Zuerst ChaCha20 entschlüsseln
        if (level == SecurityLevel::LEVEL_5) {
            std::vector<uint8_t> chacha20Decrypted;
            if (!decryptChaCha20(buffer, chacha20Decrypted, params)) {
                lastError = "Fehler beim Entschlüsseln mit ChaCha20";
                return false;
            }
            buffer = std::move(chacha20Decrypted);
        }
        
        // AES entschlüsseln
        if (!decryptAES(buffer, decryptedData, params, level)) {
            lastError = "Fehler beim Entschlüsseln. Falsches Passwort oder beschädigte Datei?";
            return false;
        }
        
        // Schreibe entschlüsselte Daten
        outputFile.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
        if (!outputFile) {
            lastError = "Fehler beim Schreiben der entschlüsselten Daten";
            return false;
        }
        
        // Aktualisiere Fortschritt
        processedBytes += bytesRead;
        if (progressCallback && totalSize > 0) {
            progressCallback(static_cast<float>(processedBytes) / totalSize);
        }
    }
    
    // Erfolg!
    return true;
}

// Letzte Fehlermeldung abrufen
std::string Crypto::getLastError() {
    return lastError;
}

// Einfacher Test der Verschlüsselungsfunktionalität
bool Crypto::testEncryption(const std::string& testString, const std::string& password, SecurityLevel level) {
    try {
        std::cerr << "DEBUG: Testing encryption with string: " << testString << std::endl;
        
        // Convert string to bytes
        std::vector<uint8_t> input(testString.begin(), testString.end());
        std::vector<uint8_t> output;
        
        // Generate crypto params and derive key
        CryptoParams params = CryptoParams::generateForEncryption(level);
        params = deriveKeyFromPassword(password, params.salt, level);
        
        if (params.key.empty()) {
            std::cerr << "DEBUG: Key derivation failed: " << lastError << std::endl;
            return false;
        }
        
        // Encrypt the string
        bool success = encryptAES(input, output, params, level);
        
        if (!success) {
            std::cerr << "DEBUG: Failed to encrypt test string: " << lastError << std::endl;
            return false;
        }
        
        std::cerr << "DEBUG: Successfully encrypted test string" << std::endl;
        
        // Now decrypt it
        std::vector<uint8_t> decrypted;
        success = decryptAES(output, decrypted, params, level);
        
        if (!success) {
            std::cerr << "DEBUG: Failed to decrypt test string: " << lastError << std::endl;
            return false;
        }
        
        std::string decryptedString(decrypted.begin(), decrypted.end());
        std::cerr << "DEBUG: Successfully decrypted: " << decryptedString << std::endl;
        
        // Verify it matches the original
        if (decryptedString != testString) {
            std::cerr << "DEBUG: ERROR - Decrypted string does not match original!" << std::endl;
            return false;
        }
        
        std::cerr << "DEBUG: Test successful - encryption and decryption work correctly" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "DEBUG: Exception during encryption test: " << e.what() << std::endl;
        lastError = "Fehler beim Verschlüsselungstest: ";
        lastError += e.what();
        return false;
    } catch (...) {
        std::cerr << "DEBUG: Unknown exception during encryption test" << std::endl;
        lastError = "Unbekannter Fehler beim Verschlüsselungstest";
        return false;
    }
}

} // namespace encrypt