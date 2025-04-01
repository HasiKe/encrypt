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

// OpenSSL-Header (nur wenn nicht simuliert)
#ifndef USE_SIMPLE_CRYPTO
// Linux-Version mit OpenSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#else
// Windows-Version mit einfachen eigenen Krypto-Funktionen
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <random>

// Konstanten definieren
#define SHA512_DIGEST_LENGTH 64
#define GCM_TAG_SIZE 16

// Einfache Krypto-Utilities für Windows
namespace simple_crypto {
    // Generiere Zufallszahlen
    inline void random_bytes(uint8_t* buf, size_t len) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 255);
        
        for (size_t i = 0; i < len; i++) {
            buf[i] = static_cast<uint8_t>(dis(gen));
        }
    }
    
    // Einfache XOR-basierte Verschlüsselung für Windows-Version
    inline void xor_encrypt(const uint8_t* input, uint8_t* output, size_t len, 
                          const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen) {
        // Verwende Key und IV um einen "Keystream" zu erzeugen
        for (size_t i = 0; i < len; i++) {
            output[i] = input[i] ^ key[i % keylen] ^ iv[i % ivlen] ^ 
                      static_cast<uint8_t>((i * 7 + 13) & 0xFF); // Einfache Diffusion
        }
    }
    
    // Einfache Key-Derivation für Windows-Version
    inline void derive_key(const char* password, size_t passlen,
                         const uint8_t* salt, size_t saltlen,
                         uint8_t* key, size_t keylen, int iterations) {
        // Initialisiere Schlüssel mit Salt
        for (size_t i = 0; i < keylen; i++) {
            key[i] = (i < saltlen) ? salt[i] : 0;
        }
        
        // Einfaches Key-Stretching
        for (int iter = 0; iter < iterations; iter++) {
            for (size_t i = 0; i < keylen; i++) {
                // Mix Password und bisherigen Key
                key[i] ^= (i < passlen) ? password[i % passlen] : 0x42;
                
                // Diffusion: Mische mit benachbarten Bytes
                if (i > 0) key[i] ^= key[i-1] >> 1;
                if (i < keylen-1) key[i] ^= key[i+1] << 1;
                
                // Nicht-Linearität: Verwende einfache Substitution
                key[i] = (key[i] * 13 + iter) & 0xFF;
            }
        }
    }
    
    // Ein sehr einfacher "Authentifizierungs-Tag" Generator
    inline void generate_mac(const uint8_t* data, size_t datalen,
                           const uint8_t* key, size_t keylen,
                           uint8_t* mac, size_t maclen) {
        // Initialisiere mit Schlüssel
        for (size_t i = 0; i < maclen; i++) {
            mac[i] = (i < keylen) ? key[i] : 0;
        }
        
        // Verarbeite Daten in Blöcken von 16 Bytes
        const size_t blocksize = 16;
        uint8_t block[blocksize];
        
        for (size_t block_start = 0; block_start < datalen; block_start += blocksize) {
            // Fülle Block mit Daten oder Nullen
            size_t bytes_to_process = std::min(blocksize, datalen - block_start);
            std::memcpy(block, data + block_start, bytes_to_process);
            
            if (bytes_to_process < blocksize) {
                std::memset(block + bytes_to_process, 0, blocksize - bytes_to_process);
            }
            
            // Mische Block in MAC
            for (size_t i = 0; i < maclen; i++) {
                mac[i] ^= block[i % blocksize];
                mac[i] = (mac[i] << 1) | (mac[i] >> 7); // Rotation
            }
            
            // Diffusion zwischen MAC-Bytes
            for (size_t i = 1; i < maclen; i++) {
                mac[i] ^= mac[i-1];
            }
        }
    }
    
    // Verifiziert MAC
    inline bool verify_mac(const uint8_t* data, size_t datalen,
                          const uint8_t* key, size_t keylen,
                          const uint8_t* expected_mac, size_t maclen) {
        uint8_t computed_mac[GCM_TAG_SIZE];
        generate_mac(data, datalen, key, keylen, computed_mac, maclen);
        
        // Konstante-Zeit Vergleich
        int result = 0;
        for (size_t i = 0; i < maclen; i++) {
            result |= (computed_mac[i] ^ expected_mac[i]);
        }
        return (result == 0);
    }
}
#endif

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
    
#ifndef USE_SIMPLE_CRYPTO
    // OpenSSL-Version
    PKCS5_PBKDF2_HMAC(
        static_cast<const char*>(pwd), static_cast<int>(pwdlen),
        static_cast<const unsigned char*>(salt), static_cast<int>(saltlen),
        100000 + t_cost * 10000, // Simuliere höhere Kosten
        EVP_sha512(),
        static_cast<int>(hashlen),
        static_cast<unsigned char*>(hash)
    );
#else
    // Windows-Simple-Crypto-Version
    simple_crypto::derive_key(
        static_cast<const char*>(pwd), pwdlen,
        static_cast<const uint8_t*>(salt), saltlen,
        static_cast<uint8_t*>(hash), hashlen,
        100000 + t_cost * 10000 // Simuliere höhere Kosten
    );
#endif
    
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
#if defined(USE_LIBSODIUM) && !defined(SIMULATED_SODIUM)
#include <sodium.h>
#elif defined(SIMULATED_SODIUM)
// Simulierte Sodium-Funktionen
extern "C" {
    int sodium_init() { return 0; }
    int crypto_stream_chacha20_xor(unsigned char* c, const unsigned char* m, 
                                  unsigned long long mlen, const unsigned char* n, 
                                  const unsigned char* k) {
        // Einfache XOR-Operation für die Simulation
        for (unsigned long long i = 0; i < mlen; i++) {
            c[i] = m[i] ^ (k[i % 32] ^ n[i % 12]);
        }
        return 0;
    }
}
#endif

namespace encrypt {

using namespace crypto_constants;

// Static Variablen initialisieren
thread_local std::string Crypto::lastError;

#ifdef SIMULATED_OPENSSL
// Implementierung der simulierten OpenSSL-Funktionen
EVP_CIPHER_CTX* EVP_CIPHER_CTX_new() { return new EVP_CIPHER_CTX(); }
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx) { delete ctx; }
const EVP_CIPHER* EVP_aes_128_gcm() { static EVP_CIPHER c; return &c; }
const EVP_CIPHER* EVP_aes_256_gcm() { static EVP_CIPHER c; return &c; }
const EVP_CIPHER* EVP_chacha20() { static EVP_CIPHER c; return &c; }
const EVP_CIPHER* EVP_sha512() { static EVP_CIPHER c; return &c; }
int EVP_EncryptInit_ex(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*) { return 1; }
int EVP_EncryptUpdate(EVP_CIPHER_CTX*, unsigned char* out, int* outl, const unsigned char* in, int inl) { 
    *outl = inl; 
    if (out && in && inl > 0) std::memcpy(out, in, inl); 
    return 1; 
}
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX*, unsigned char*, int* outl) { *outl = 0; return 1; }
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX*, int, int, void*) { return 1; }
int EVP_DecryptInit_ex(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*) { return 1; }
int EVP_DecryptUpdate(EVP_CIPHER_CTX*, unsigned char* out, int* outl, const unsigned char* in, int inl) { 
    *outl = inl; 
    if (out && in && inl > 0) std::memcpy(out, in, inl); 
    return 1; 
}
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX*, unsigned char*, int* outl) { *outl = 0; return 1; }
int EVP_CIPHER_block_size(const EVP_CIPHER*) { return 16; }
unsigned long ERR_get_error() { return 0; }
void ERR_error_string_n(unsigned long, char* buf, size_t) { std::strcpy(buf, "Simulierter OpenSSL-Fehler"); }
int RAND_bytes(unsigned char* buf, int num) { 
    static bool seeded = false;
    if (!seeded) {
        std::srand(static_cast<unsigned int>(std::time(nullptr)));
        seeded = true;
    }
    for (int i = 0; i < num; i++) {
        buf[i] = static_cast<unsigned char>(std::rand() % 256);
    }
    return 1; 
}
int PKCS5_PBKDF2_HMAC(const char* pass, int passlen, const unsigned char* salt, int saltlen, int, const EVP_CIPHER*, int keylen, unsigned char* out) { 
    // Einfache Hash-Simulation
    for (int i = 0; i < keylen; i++) {
        out[i] = (i < passlen ? pass[i] : 0) ^ (i < saltlen ? salt[i % saltlen] : 0);
    }
    return 1; 
}
HMAC_CTX* HMAC_CTX_new() { return new HMAC_CTX(); }
void HMAC_CTX_free(HMAC_CTX* ctx) { delete ctx; }
int HMAC_Init_ex(HMAC_CTX*, const void*, int, const EVP_CIPHER*, ENGINE*) { return 1; }
int HMAC_Update(HMAC_CTX*, const unsigned char*, size_t) { return 1; }
int HMAC_Final(HMAC_CTX*, unsigned char* md, unsigned int* len) { 
    *len = SHA512_DIGEST_LENGTH; 
    std::memset(md, 0, SHA512_DIGEST_LENGTH); 
    return 1; 
}
#endif

// Hilfsfunktion für Fehler
std::string getOpenSSLError() {
#ifndef USE_SIMPLE_CRYPTO
    char errbuf[256];
    unsigned long err = ERR_get_error();
    if (err == 0) {
        return "Kein OpenSSL-Fehler";
    }
    ERR_error_string_n(err, errbuf, sizeof(errbuf));
    return errbuf;
#else
    return "Fehler bei der Kryptographie-Operation";
#endif
}

// Zufällige Bytes generieren
std::vector<uint8_t> Crypto::generateRandomBytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    
#ifndef USE_SIMPLE_CRYPTO
    // OpenSSL-Version
    int result = RAND_bytes(bytes.data(), static_cast<int>(length));
    if (result != 1) {
        lastError = "Fehler beim Generieren von Zufallszahlen: " + getOpenSSLError();
        return {};
    }
#else
    // Simple-Crypto-Version für Windows
    simple_crypto::random_bytes(bytes.data(), length);
#endif
    
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
    
#ifndef USE_SIMPLE_CRYPTO
    // OpenSSL-Version
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
#else
    // Simple-Crypto-Version für Windows
    // Vereinfachte Schlüsselableitung basierend auf Sicherheitsstufe
    int iterations;
    switch (level) {
        case SecurityLevel::LEVEL_1: iterations = 10000; break;
        case SecurityLevel::LEVEL_2: iterations = 20000; break;
        case SecurityLevel::LEVEL_3: iterations = 50000; break;
        case SecurityLevel::LEVEL_4: iterations = 75000; break;
        case SecurityLevel::LEVEL_5: iterations = 100000; break;
        default: iterations = 20000; break;
    }
    
    // Ableiten des Hauptschlüssels
    simple_crypto::derive_key(
        password.c_str(), password.length(),
        salt.data(), salt.size(),
        params.key.data(), keySize,
        iterations
    );
    
    // Bei Level 5 den Schlüssel verdoppeln für ChaCha20
    if (level == SecurityLevel::LEVEL_5) {
        size_t originalKeySize = params.key.size();
        params.key.resize(originalKeySize * 2);
        
        // Einfache Ableitung für den zweiten Teil
        uint8_t tempKey[SHA512_DIGEST_LENGTH];
        
        for (size_t i = 0; i < SHA512_DIGEST_LENGTH; i++) {
            tempKey[i] = params.key[i % originalKeySize] ^ salt[i % salt.size()] ^ 0xA5;
        }
        
        // Kopiere in den zweiten Teil des Schlüssels
        std::copy_n(tempKey, originalKeySize, params.key.data() + originalKeySize);
    }
#endif
    
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
    
#ifndef USE_SIMPLE_CRYPTO
    // OpenSSL-Version
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
#else
    // Windows-Version mit Simple-Crypto
    std::cerr << "DEBUG: Using simple crypto for Windows" << std::endl;
    std::cerr << "DEBUG: Key size: " << params.key.size() << " bytes, IV size: " << params.iv.size() << " bytes" << std::endl;
    
    // Überprüfe Schlüssel- und IV-Größe
    if (params.key.empty() || params.iv.empty()) {
        lastError = "Ungültige Krypto-Parameter (Schlüssel oder IV fehlt)";
        return false;
    }
    
    // Reserviere Ausgabepuffer
    output.resize(input.size());
    
    // Einfache XOR-Verschlüsselung
    simple_crypto::xor_encrypt(
        input.data(), output.data(), input.size(),
        params.key.data(), params.key.size(),
        params.iv.data(), params.iv.size()
    );
    
    // Generiere einen MAC-Tag
    std::vector<uint8_t> tag(GCM_TAG_SIZE);
    simple_crypto::generate_mac(
        output.data(), output.size(),
        params.key.data(), params.key.size(),
        tag.data(), tag.size()
    );
    
    // Speichere das Authentication-Tag
    const_cast<CryptoParams&>(params).authTag = std::move(tag);
    
    std::cerr << "DEBUG: Simple crypto encryption complete" << std::endl;
    std::cerr << "DEBUG: Auth tag size: " << params.authTag.size() << " bytes" << std::endl;
#endif
    
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
    
#ifndef USE_SIMPLE_CRYPTO
    // OpenSSL-Version
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
#else
    // Windows-Version mit Simple-Crypto
    std::cerr << "DEBUG: Using simple crypto for Windows decryption" << std::endl;
    
    // Überprüfe Parameter
    if (params.key.empty() || params.iv.empty() || params.authTag.empty()) {
        lastError = "Ungültige Krypto-Parameter (Schlüssel, IV oder Auth-Tag fehlt)";
        return false;
    }
    
    // Verifiziere die Authentizität der Daten
    if (!simple_crypto::verify_mac(
            input.data(), input.size(),
            params.key.data(), params.key.size(),
            params.authTag.data(), params.authTag.size())) {
        lastError = "Authentizitätsprüfung fehlgeschlagen: Die Daten wurden möglicherweise manipuliert";
        return false;
    }
    
    // Reserviere Ausgabepuffer
    output.resize(input.size());
    
    // Einfache XOR-Entschlüsselung (identisch zur Verschlüsselung bei XOR-Cipher)
    simple_crypto::xor_encrypt(
        input.data(), output.data(), input.size(),
        params.key.data(), params.key.size(),
        params.iv.data(), params.iv.size()
    );
    
    std::cerr << "DEBUG: Simple crypto decryption complete" << std::endl;
    std::cerr << "DEBUG: Decrypted size: " << output.size() << " bytes" << std::endl;
#endif
    
    return true;
}

// ChaCha20-Verschlüsselung für Sicherheitsstufe 5
bool Crypto::encryptChaCha20(
    const std::vector<uint8_t>& input, 
    std::vector<uint8_t>& output,
    const CryptoParams& params
) {
#ifdef USE_SIMPLE_CRYPTO
    // Windows-Version mit Simple-Crypto
    output.resize(input.size());
    
    // Parameter extrahieren
    const uint8_t* key = params.key.data() + KEY_SIZE_LEVEL_5; // Zweiter Teil des Schlüssels
    const uint8_t* nonce = params.iv.data() + IV_SIZE;         // ChaCha20-Nonce ist nach dem IV
    
    // Für Windows vereinfachen wir und nutzen die gleiche XOR-Funktion mit anderem Schlüssel
    simple_crypto::xor_encrypt(
        input.data(), output.data(), input.size(),
        key, KEY_SIZE_LEVEL_5,
        nonce, CHACHA_NONCE_SIZE
    );
    
    return true;
#elif defined(USE_LIBSODIUM)
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
#ifdef USE_SIMPLE_CRYPTO
    // Windows-Version mit Simple-Crypto (bei XOR-Verschlüsselung ist Entschlüsselung gleich)
    return encryptChaCha20(input, output, params);
#elif defined(USE_LIBSODIUM)
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
    
    // Vermeide Selbstüberschreibung bei Entschlüsselung
    if (inputFileName == outputFileName) {
        lastError = "Eingabe- und Ausgabedatei dürfen nicht identisch sein";
        return false;
    }
    
    // Öffne Ausgabedatei
    std::ofstream outputFile(outputFileName, std::ios::binary | std::ios::trunc);
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
        std::cerr << "DEBUG: Original IV size before key derivation: " << params.iv.size() << " bytes" << std::endl;
        
        // Speichere IV, da deriveKeyFromPassword diese überschreiben kann
        std::vector<uint8_t> savedIV = params.iv;
        
        // Leite den Schlüssel ab
        CryptoParams keyParams = deriveKeyFromPassword(password, params.salt, level);
        if (keyParams.key.empty()) {
            // Fehlermeldung wurde bereits in deriveKeyFromPassword gesetzt
            std::cerr << "DEBUG: Key derivation failed: " << lastError << std::endl;
            return false;
        }
        
        // Übernimm nur den Schlüssel, behalte den IV
        params.key = keyParams.key;
        
        // Stelle sicher, dass der IV nicht verloren geht
        if (params.iv.empty() && !savedIV.empty()) {
            params.iv = savedIV;
        }
        
        std::cerr << "DEBUG: IV size after key derivation: " << params.iv.size() << " bytes" << std::endl;
        
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
            
            // Temporäre Kopie des Auth-Tags sichern
            std::vector<uint8_t> savedAuthTag = params.authTag;
            
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
            
            // Write the GCM authentication tag for filename
            std::cerr << "DEBUG: Writing auth tag for filename" << std::endl;
            outputFile.put(HEADER_TAG_AUTH_TAG);
            outputFile.put(static_cast<char>(params.authTag.size()));
            outputFile.write(reinterpret_cast<const char*>(params.authTag.data()), params.authTag.size());
            
            // Restore the original authTag if any
            if (!savedAuthTag.empty()) {
                params.authTag = std::move(savedAuthTag);
            }
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
            // Kopie der Parameter, um nicht mit den originalen zu arbeiten
            CryptoParams processorParams = params;

            auto processor = [processorParams, level](const std::vector<uint8_t>& input, std::vector<uint8_t>& output) mutable -> bool {
                std::cerr << "DEBUG: Processing chunk of size " << input.size() << std::endl;
                
                // Verschlüssele mit AES
                if (!Crypto::encryptAES(input, output, processorParams, level)) {
                    std::cerr << "DEBUG: AES encryption failed: " << Crypto::getLastError() << std::endl;
                    return false;
                }
                
                // Für Sicherheitsstufe 5: Zusätzliche ChaCha20-Verschlüsselung
                if (level == SecurityLevel::LEVEL_5) {
                    std::vector<uint8_t> chacha20Output;
                    if (!Crypto::encryptChaCha20(output, chacha20Output, processorParams)) {
                        std::cerr << "DEBUG: ChaCha20 encryption failed: " << Crypto::getLastError() << std::endl;
                        return false;
                    }
                    output = std::move(chacha20Output);
                }
                
                // Füge den Auth-Tag hinzu
                std::vector<uint8_t> withTag = output;
                withTag.insert(withTag.end(), processorParams.authTag.begin(), processorParams.authTag.end());
                output = std::move(withTag);
                
                return true;
            };
            
            // WICHTIG: Hier dürfen wir outputFileName nicht neu öffnen, da wir bereits einen Header geschrieben haben
            // Stattdessen bearbeiten wir die Datei manuell weiter
            
            // Puffergröße für Chunks
            constexpr size_t bufferSize = 64 * 1024;
            std::vector<uint8_t> inputBuffer(bufferSize);
            std::vector<uint8_t> outputBuffer;
            
            // Öffne Eingabedatei
            std::ifstream inputFile(inputFileName, std::ios::binary);
            if (!inputFile) {
                lastError = "Fehler beim Öffnen der Eingabedatei: " + inputFileName;
                return false;
            }
            
            // Berechne Dateigröße für Fortschrittsberechnung
            inputFile.seekg(0, std::ios::end);
            std::streamsize totalSize = inputFile.tellg();
            inputFile.seekg(0, std::ios::beg);
            
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
                
                // Schreibe verarbeitete Daten an das Ende der bereits geöffneten Datei
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
    
    // Sichern des IVs, da dieser bei deriveKeyFromPassword verloren gehen könnte
    std::vector<uint8_t> savedIV = iv;
    
    // Schüssel vom Passwort ableiten
    CryptoParams keyParams = deriveKeyFromPassword(password, salt, level);
    if (keyParams.key.empty()) {
        // Fehlermeldung wurde bereits in deriveKeyFromPassword gesetzt
        return false;
    }
    
    // Nur den Schlüssel übernehmen, IV und authTag behalten
    params.key = keyParams.key;
    
    // Sicherstellen, dass IV nicht verloren geht
    if (params.iv.empty() && !savedIV.empty()) {
        params.iv = savedIV;
    }
    
    std::cerr << "DEBUG: Decryption key derived, key size: " << params.key.size() 
              << ", IV size: " << params.iv.size() 
              << ", auth tag size: " << params.authTag.size() << std::endl;
    
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
    std::cerr << "DEBUG: Header ended at position: " << dataStart << std::endl;
    
    // Öffne die Ausgabedatei für die entschlüsselten Daten
    std::ofstream outputFile(finalOutputFileName, std::ios::binary);
    if (!outputFile) {
        lastError = "Fehler beim Erstellen der Ausgabedatei: " + finalOutputFileName;
        return false;
    }
    
    // Bei der Entschlüsselung werden wir die Daten manuell verarbeiten
    // Puffergröße für Chunks (64 KB + Platz für Auth-Tag)
    const size_t chunkSize = 64 * 1024;
    const size_t bufferSize = chunkSize + GCM_TAG_SIZE;
    std::vector<uint8_t> buffer(bufferSize);
    
    // Dateigröße für Fortschrittsberechnung
    inputFile.seekg(0, std::ios::end);
    std::streamsize totalSize = inputFile.tellg() - dataStart;
    inputFile.seekg(dataStart, std::ios::beg);
    
    // Verarbeite verschlüsselte Daten in Chunks
    std::streamsize processedBytes = 0;
    std::streamsize totalDecryptedBytes = 0; // Zählt die Gesamtgröße der entschlüsselten Daten
    
    try {
        std::cerr << "DEBUG: Decryption - Starting to read data from position: " 
                  << inputFile.tellg() << ", total file size: " << totalSize << std::endl;
        
        // Führe eine Analyse der Datei durch
        std::vector<uint8_t> firstBytes(std::min(static_cast<std::streamsize>(32), totalSize));
        if (!firstBytes.empty()) {
            inputFile.read(reinterpret_cast<char*>(firstBytes.data()), firstBytes.size());
            std::cerr << "DEBUG: First bytes of encrypted data: ";
            for (size_t i = 0; i < firstBytes.size() && i < 16; ++i) {
                std::cerr << std::hex << std::setw(2) << std::setfill('0') 
                          << static_cast<int>(firstBytes[i]) << " ";
            }
            std::cerr << std::dec << std::endl;
            
            // Zurück zur Startposition
            inputFile.seekg(dataStart, std::ios::beg);
        }
        
        while (inputFile) {
            // Lese einen Chunk der verschlüsselten Daten
            inputFile.read(reinterpret_cast<char*>(buffer.data()), bufferSize);
            std::streamsize bytesRead = inputFile.gcount();
            
            std::cerr << "DEBUG: Decryption - Read " << bytesRead << " bytes from encrypted file" << std::endl;
            
            if (bytesRead <= 0) {
                std::cerr << "DEBUG: No more data to read (bytesRead=" << bytesRead << ")" << std::endl;
                break;  // Keine weiteren Daten
            }
            
            if (bytesRead < static_cast<std::streamsize>(GCM_TAG_SIZE)) {
                std::cerr << "DEBUG: Error - Chunk too small for auth tag: " << bytesRead << " < " << GCM_TAG_SIZE << std::endl;
                lastError = "Ungültiges Datenformat: Chunk zu klein für Auth-Tag";
                return false;
            }
            
            // Passe die Puffergröße an die tatsächlich gelesenen Bytes an
            buffer.resize(static_cast<size_t>(bytesRead));
            
            // Trenne verschlüsselte Daten vom Auth-Tag
            size_t dataSize = buffer.size() - GCM_TAG_SIZE;
            params.authTag.assign(buffer.begin() + dataSize, buffer.end());
            
            std::cerr << "DEBUG: Extracted auth tag size: " << params.authTag.size() << " bytes" << std::endl;
            std::cerr << "DEBUG: Decryption - Data size without tag: " << dataSize << " bytes" << std::endl;
            
            // Extrahiere nur die verschlüsselten Daten
            std::vector<uint8_t> encryptedData(buffer.begin(), buffer.begin() + dataSize);
            
            // Für Sicherheitsstufe 5: Zuerst ChaCha20 entschlüsseln
            if (level == SecurityLevel::LEVEL_5) {
                std::vector<uint8_t> chacha20Decrypted;
                if (!decryptChaCha20(encryptedData, chacha20Decrypted, params)) {
                    std::cerr << "DEBUG: Error decrypting with ChaCha20: " << lastError << std::endl;
                    lastError = "Fehler beim Entschlüsseln mit ChaCha20";
                    return false;
                }
                encryptedData = std::move(chacha20Decrypted);
            }
            
            // AES entschlüsseln
            std::vector<uint8_t> decryptedData;
            if (!decryptAES(encryptedData, decryptedData, params, level)) {
                std::cerr << "DEBUG: Error decrypting with AES: " << lastError << std::endl;
                lastError = "Fehler beim Entschlüsseln. Falsches Passwort oder beschädigte Datei?";
                return false;
            }
            
            std::cerr << "DEBUG: Decrypted data size: " << decryptedData.size() << " bytes" << std::endl;
            if (!decryptedData.empty()) {
                std::cerr << "DEBUG: First bytes of decrypted data: ";
                for (size_t i = 0; i < std::min(size_t(16), decryptedData.size()); ++i) {
                    std::cerr << std::hex << std::setw(2) << std::setfill('0') 
                              << static_cast<int>(decryptedData[i]) << " ";
                }
                std::cerr << std::dec << std::endl;
            }
            
            // Schreibe entschlüsselte Daten in die Ausgabedatei
            outputFile.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
            if (!outputFile) {
                std::cerr << "DEBUG: Error writing to output file" << std::endl;
                lastError = "Fehler beim Schreiben der entschlüsselten Daten";
                return false;
            }
            
            totalDecryptedBytes += decryptedData.size();
            std::cerr << "DEBUG: Total decrypted bytes so far: " << totalDecryptedBytes << std::endl;
            
            // Fortschritt aktualisieren
            processedBytes += bytesRead;
            if (progressCallback && totalSize > 0) {
                progressCallback(static_cast<float>(processedBytes) / totalSize);
            }
        }
        
        // Abschließender Fortschritt
        if (progressCallback) {
            progressCallback(1.0f);
        }
        
        // Stellen Sie sicher, dass Daten auf die Festplatte geschrieben werden
        outputFile.flush();
        
        // Überprüfen Sie, ob überhaupt Daten entschlüsselt wurden
        if (totalDecryptedBytes == 0) {
            std::cerr << "DEBUG: WARNING - Zero bytes decrypted in total!" << std::endl;
            lastError = "Fehler: Keine Daten wurden entschlüsselt.";
            return false;
        } else {
            std::cerr << "DEBUG: Successfully decrypted " << totalDecryptedBytes << " bytes in total" << std::endl;
        }
        
        // Dateien schließen
        inputFile.close();
        outputFile.close();
        
        // Überprüfen Sie die Ausgabedatei
        std::ifstream checkFile(finalOutputFileName, std::ios::binary);
        if (checkFile) {
            checkFile.seekg(0, std::ios::end);
            std::streamsize fileSize = checkFile.tellg();
            checkFile.close();
            std::cerr << "DEBUG: Final output file size: " << fileSize << " bytes" << std::endl;
            
            if (fileSize == 0 && totalDecryptedBytes > 0) {
                std::cerr << "DEBUG: ERROR - File is empty but we decrypted " << totalDecryptedBytes << " bytes!" << std::endl;
                lastError = "Fehler: Ausgabedatei ist leer, obwohl Daten entschlüsselt wurden.";
                return false;
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        lastError = "Fehler bei der Entschlüsselung: ";
        lastError += e.what();
        return false;
    }
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
        
        // Manuell Crypto-Parameter erstellen
        CryptoParams params;
        
        // Salt und IV erzeugen
        std::cerr << "DEBUG: Generating random bytes for salt and IV" << std::endl;
        std::vector<uint8_t> salt = generateRandomBytes(SALT_SIZE);
        std::vector<uint8_t> iv = generateRandomBytes(IV_SIZE);
        
        std::cerr << "DEBUG: Created salt (size: " << salt.size() << " bytes)" << std::endl;
        std::cerr << "DEBUG: Created IV (size: " << iv.size() << " bytes)" << std::endl;
        
        // Parameter manuell setzen
        params.salt = salt;
        params.iv = iv;
        
        // Leite Schlüssel vom Passwort ab
        std::cerr << "DEBUG: Deriving key from password" << std::endl;
        CryptoParams keyParams = deriveKeyFromPassword(password, params.salt, level);
        params.key = keyParams.key;
        
        if (params.key.empty()) {
            std::cerr << "DEBUG: Key derivation failed: " << lastError << std::endl;
            return false;
        }
        
        std::cerr << "DEBUG: Key derived successfully (size: " << params.key.size() << " bytes)" << std::endl;
        std::cerr << "DEBUG: Salt size: " << params.salt.size() << " bytes" << std::endl;
        std::cerr << "DEBUG: IV size: " << params.iv.size() << " bytes" << std::endl;
        
        // Encrypt the string
        std::cerr << "DEBUG: Encrypting test string" << std::endl;
        bool success = encryptAES(input, output, params, level);
        
        if (!success) {
            std::cerr << "DEBUG: Failed to encrypt test string: " << lastError << std::endl;
            return false;
        }
        
        std::cerr << "DEBUG: Successfully encrypted test string" << std::endl;
        std::cerr << "DEBUG: Auth tag size: " << params.authTag.size() << " bytes" << std::endl;
        
        // Now decrypt it
        std::cerr << "DEBUG: Decrypting test string" << std::endl;
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

// Struktur zum Speichern von Ordnerdaten
struct FolderEntry {
    std::string relativePath;  // Relativer Pfad innerhalb des Ordners
    std::vector<uint8_t> data; // Dateiinhalt
    size_t originalSize;       // Originalgröße der Datei
};

// Funktion zum Sammeln aller Dateien in einem Ordner rekursiv
std::vector<std::string> collectFilesInFolder(const std::string& folderPath) {
    std::vector<std::string> files;
    
    try {
        if (!std::filesystem::exists(folderPath)) {
            return files;
        }
        
        for (const auto& entry : std::filesystem::recursive_directory_iterator(folderPath)) {
            if (entry.is_regular_file()) {
                files.push_back(entry.path().string());
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Fehler beim Sammeln der Dateien: " << e.what() << std::endl;
    }
    
    return files;
}

// Ordner verschlüsseln
bool Crypto::encryptFolder(
    const std::string& inputFolderPath,
    const std::string& outputFileName,
    const std::string& password,
    SecurityLevel level,
    const std::function<void(float)>& progressCallback
) {
    std::cerr << "DEBUG: Starting folder encryption: " << inputFolderPath << std::endl;
    
    try {
        // Überprüfe, ob der Ordner existiert
        if (!std::filesystem::is_directory(inputFolderPath)) {
            lastError = "Der angegebene Pfad ist kein Ordner oder existiert nicht: " + inputFolderPath;
            return false;
        }
        
        // Sammle alle Dateien im Ordner rekursiv
        std::vector<std::string> filePaths = collectFilesInFolder(inputFolderPath);
        
        if (filePaths.empty()) {
            lastError = "Der Ordner ist leer oder enthält keine regulären Dateien";
            return false;
        }
        
        std::cerr << "DEBUG: Found " << filePaths.size() << " files in folder" << std::endl;
        
        // Erstelle CryptoParams für die Verschlüsselung
        CryptoParams params = CryptoParams::generateForEncryption(level);
        
        // Speichere IV, da deriveKeyFromPassword diese überschreiben kann
        std::vector<uint8_t> savedIV = params.iv;
        
        // Leite den Schlüssel ab
        CryptoParams keyParams = deriveKeyFromPassword(password, params.salt, level);
        if (keyParams.key.empty()) {
            return false; // Fehlermeldung wurde bereits in deriveKeyFromPassword gesetzt
        }
        
        // Übernimm nur den Schlüssel, behalte den IV
        params.key = keyParams.key;
        
        // Stelle sicher, dass der IV nicht verloren geht
        if (params.iv.empty() && !savedIV.empty()) {
            params.iv = savedIV;
        }
        
        // Erstelle die Ausgabedatei
        std::ofstream outputFile(outputFileName, std::ios::binary);
        if (!outputFile) {
            lastError = "Fehler beim Erstellen der Ausgabedatei: " + outputFileName;
            return false;
        }
        
        // 1. Schreibe Datei-Header (Signatur, Version)
        outputFile.write(reinterpret_cast<const char*>(FILE_SIGNATURE), 4);
        outputFile.put(FILE_VERSION);
        
        // 2. Markiere als Ordnerdatei
        outputFile.put(HEADER_TAG_FOLDER);
        outputFile.put(0x01);  // Ordnerversion 1
        
        // 3. Schreibe Sicherheitsstufe
        outputFile.put(HEADER_TAG_SECURITY_LEVEL);
        outputFile.put(static_cast<char>(level));
        
        // 4. Schreibe Salt
        outputFile.put(HEADER_TAG_SALT);
        outputFile.put(static_cast<char>(params.salt.size()));
        outputFile.write(reinterpret_cast<const char*>(params.salt.data()), params.salt.size());
        
        // 5. Schreibe IV
        size_t ivSize = (level == SecurityLevel::LEVEL_5) ? IV_SIZE + CHACHA_NONCE_SIZE : IV_SIZE;
        outputFile.put(HEADER_TAG_IV);
        outputFile.put(static_cast<char>(ivSize));
        outputFile.write(reinterpret_cast<const char*>(params.iv.data()), ivSize);
        
        // 6. Verschlüssle den Ordnernamen
        std::string folderName = std::filesystem::path(inputFolderPath).filename().string();
        std::vector<uint8_t> folderNameBytes(folderName.begin(), folderName.end());
        std::vector<uint8_t> encryptedFolderName;
        
        // Temporäre Kopie des Auth-Tags sichern
        std::vector<uint8_t> savedAuthTag = params.authTag;
        
        if (!encryptAES(folderNameBytes, encryptedFolderName, params, level)) {
            return false;
        }
        
        // Schreibe den verschlüsselten Ordnernamen
        outputFile.put(HEADER_TAG_FILENAME);
        uint16_t folderNameSize = static_cast<uint16_t>(encryptedFolderName.size());
        outputFile.write(reinterpret_cast<const char*>(&folderNameSize), sizeof(folderNameSize));
        outputFile.write(reinterpret_cast<const char*>(encryptedFolderName.data()), encryptedFolderName.size());
        
        // Schreibe den Auth-Tag für den Ordnernamen
        outputFile.put(HEADER_TAG_AUTH_TAG);
        outputFile.put(static_cast<char>(params.authTag.size()));
        outputFile.write(reinterpret_cast<const char*>(params.authTag.data()), params.authTag.size());
        
        // Stelle den ursprünglichen Auth-Tag wieder her
        params.authTag = savedAuthTag;
        
        // 7. Schreibe die Anzahl der Dateien
        uint32_t fileCount = static_cast<uint32_t>(filePaths.size());
        outputFile.write(reinterpret_cast<const char*>(&fileCount), sizeof(fileCount));
        
        // 8. Verarbeite jede Datei im Ordner
        size_t totalBytes = 0;
        size_t processedBytes = 0;
        
        // Berechne die Gesamtgröße für den Fortschritt
        for (const auto& filePath : filePaths) {
            if (std::filesystem::exists(filePath)) {
                totalBytes += std::filesystem::file_size(filePath);
            }
        }
        
        // Verarbeite jede Datei
        for (size_t fileIndex = 0; fileIndex < filePaths.size(); fileIndex++) {
            const std::string& filePath = filePaths[fileIndex];
            
            // Relativen Pfad innerhalb des Ordners berechnen
            std::string relativePath = filePath.substr(inputFolderPath.size() + 1);
            
            // Für Windows: Pfadtrenner normalisieren
            std::replace(relativePath.begin(), relativePath.end(), '\\', '/');
            
            std::cerr << "DEBUG: Processing file " << (fileIndex + 1) << "/" << filePaths.size() << ": " 
                      << relativePath << std::endl;
            
            // Markiere Beginn eines Dateieintrags
            outputFile.put(HEADER_TAG_FILE_ENTRY);
            
            // Verschlüssele den relativen Pfad
            std::vector<uint8_t> pathBytes(relativePath.begin(), relativePath.end());
            std::vector<uint8_t> encryptedPath;
            
            savedAuthTag = params.authTag;
            
            if (!encryptAES(pathBytes, encryptedPath, params, level)) {
                return false;
            }
            
            // Schreibe den verschlüsselten Pfad
            outputFile.put(HEADER_TAG_FILE_PATH);
            uint16_t pathSize = static_cast<uint16_t>(encryptedPath.size());
            outputFile.write(reinterpret_cast<const char*>(&pathSize), sizeof(pathSize));
            outputFile.write(reinterpret_cast<const char*>(encryptedPath.data()), encryptedPath.size());
            
            // Schreibe den Auth-Tag für den Pfad
            outputFile.put(HEADER_TAG_AUTH_TAG);
            outputFile.put(static_cast<char>(params.authTag.size()));
            outputFile.write(reinterpret_cast<const char*>(params.authTag.data()), params.authTag.size());
            
            // Stelle den ursprünglichen Auth-Tag wieder her
            params.authTag = savedAuthTag;
            
            // Lese die Datei ein
            std::ifstream inputFile(filePath, std::ios::binary);
            if (!inputFile) {
                std::cerr << "WARNUNG: Datei konnte nicht geöffnet werden: " << filePath << std::endl;
                continue;
            }
            
            // Bestimme die Dateigröße
            inputFile.seekg(0, std::ios::end);
            size_t fileSize = static_cast<size_t>(inputFile.tellg());
            inputFile.seekg(0, std::ios::beg);
            
            // Schreibe die originale Dateigröße
            outputFile.put(HEADER_TAG_FILE_SIZE);
            outputFile.write(reinterpret_cast<const char*>(&fileSize), sizeof(fileSize));
            
            // Wenn die Datei leer ist, fahre mit der nächsten fort
            if (fileSize == 0) {
                continue;
            }
            
            // Lese den Dateiinhalt
            std::vector<uint8_t> fileData(fileSize);
            if (!inputFile.read(reinterpret_cast<char*>(fileData.data()), fileSize)) {
                std::cerr << "WARNUNG: Fehler beim Lesen der Datei: " << filePath << std::endl;
                continue;
            }
            
            // Verschlüssele den Dateiinhalt
            std::vector<uint8_t> encryptedData;
            
            savedAuthTag = params.authTag;
            
            if (!encryptAES(fileData, encryptedData, params, level)) {
                return false;
            }
            
            // Für Sicherheitsstufe 5: Zusätzliche ChaCha20-Verschlüsselung
            if (level == SecurityLevel::LEVEL_5) {
                std::vector<uint8_t> chacha20Output;
                if (!encryptChaCha20(encryptedData, chacha20Output, params)) {
                    return false;
                }
                encryptedData = std::move(chacha20Output);
            }
            
            // Schreibe die verschlüsselten Daten
            outputFile.put(HEADER_TAG_FILE_DATA);
            uint32_t encryptedSize = static_cast<uint32_t>(encryptedData.size());
            outputFile.write(reinterpret_cast<const char*>(&encryptedSize), sizeof(encryptedSize));
            outputFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
            
            // Schreibe den Auth-Tag
            outputFile.put(HEADER_TAG_AUTH_TAG);
            outputFile.put(static_cast<char>(params.authTag.size()));
            outputFile.write(reinterpret_cast<const char*>(params.authTag.data()), params.authTag.size());
            
            // Aktualisiere den Fortschritt
            processedBytes += fileSize;
            if (progressCallback && totalBytes > 0) {
                progressCallback(static_cast<float>(processedBytes) / totalBytes);
            }
            
            // Stelle den ursprünglichen Auth-Tag wieder her
            params.authTag = savedAuthTag;
        }
        
        // Abschließender Fortschritt
        if (progressCallback) {
            progressCallback(1.0f);
        }
        
        std::cerr << "DEBUG: Folder encryption completed successfully" << std::endl;
        return true;
    } catch (const std::exception& e) {
        lastError = "Fehler bei der Ordnerverschlüsselung: ";
        lastError += e.what();
        return false;
    }
}

// Ordner entschlüsseln
bool Crypto::decryptFolder(
    const std::string& inputFileName,
    const std::string& password,
    const std::string& outputFolderPath,
    const std::function<void(float)>& progressCallback
) {
    std::cerr << "DEBUG: Starting folder decryption: " << inputFileName << std::endl;
    
    try {
        // Öffne die Eingabedatei
        std::ifstream inputFile(inputFileName, std::ios::binary);
        if (!inputFile) {
            lastError = "Fehler beim Öffnen der verschlüsselten Datei: " + inputFileName;
            return false;
        }
        
        // Überprüfe die Dateisignatur
        char signatureBuffer[4];
        inputFile.read(signatureBuffer, 4);
        if (!inputFile || memcmp(signatureBuffer, FILE_SIGNATURE, 4) != 0) {
            lastError = "Ungültiges Dateiformat oder keine verschlüsselte Datei";
            return false;
        }
        
        // Überprüfe die Version
        char version;
        inputFile.get(version);
        if (!inputFile || version != FILE_VERSION) {
            lastError = "Nicht unterstützte Dateiversion";
            return false;
        }
        
        // Überprüfe, ob es sich um eine Ordnerdatei handelt
        char tag;
        inputFile.get(tag);
        if (!inputFile || tag != HEADER_TAG_FOLDER) {
            lastError = "Die Datei enthält keinen verschlüsselten Ordner";
            return false;
        }
        
        // Ordnerversion prüfen
        char folderVersion;
        inputFile.get(folderVersion);
        if (!inputFile || folderVersion != 0x01) {
            lastError = "Nicht unterstützte Ordnerversion";
            return false;
        }
        
        // Header-Daten
        SecurityLevel level = SecurityLevel::LEVEL_2; // Standardwert
        std::vector<uint8_t> salt;
        std::vector<uint8_t> iv;
        std::vector<uint8_t> encryptedFolderName;
        std::vector<uint8_t> authTag;
        
        // Header-Tags lesen
        while (inputFile) {
            inputFile.get(tag);
            
            if (!inputFile) {
                lastError = "Fehler beim Lesen des Dateiheaders";
                return false;
            }
            
            // Prüfe auf Dateiende oder Ende des Headers
            if (tag == '\0' || tag >= 0x80) {
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
                        lastError = "Fehler beim Lesen der Ordnernamensgröße";
                        return false;
                    }
                    
                    encryptedFolderName.resize(fileNameSize);
                    inputFile.read(reinterpret_cast<char*>(encryptedFolderName.data()), fileNameSize);
                    if (!inputFile) {
                        lastError = "Fehler beim Lesen des verschlüsselten Ordnernamens";
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
        
        // Sichern des IVs, da dieser bei deriveKeyFromPassword verloren gehen könnte
        std::vector<uint8_t> savedIV = iv;
        
        // Schüssel vom Passwort ableiten
        CryptoParams keyParams = deriveKeyFromPassword(password, salt, level);
        if (keyParams.key.empty()) {
            return false; // Fehlermeldung wurde bereits in deriveKeyFromPassword gesetzt
        }
        
        // Nur den Schlüssel übernehmen, IV und authTag behalten
        params.key = keyParams.key;
        
        // Sicherstellen, dass IV nicht verloren geht
        if (params.iv.empty() && !savedIV.empty()) {
            params.iv = savedIV;
        }
        
        // Ordnernamen entschlüsseln
        std::vector<uint8_t> decryptedFolderNameBytes;
        if (!decryptAES(encryptedFolderName, decryptedFolderNameBytes, params, level)) {
            lastError = "Fehler beim Entschlüsseln des Ordnernamens. Falsches Passwort?";
            return false;
        }
        
        std::string decryptedFolderName(decryptedFolderNameBytes.begin(), decryptedFolderNameBytes.end());
        
        // Bestimme den Ausgabeordner
        std::string finalOutputFolderPath;
        if (!outputFolderPath.empty()) {
            finalOutputFolderPath = outputFolderPath;
        } else {
            // Verwende den entschlüsselten Ordnernamen im aktuellen Verzeichnis
            finalOutputFolderPath = std::filesystem::path(inputFileName).parent_path().string();
            finalOutputFolderPath = finalOutputFolderPath + "/" + decryptedFolderName;
            
            // Falls der Ordner bereits existiert, füge "(Wiederhergestellt)" hinzu
            if (std::filesystem::exists(finalOutputFolderPath)) {
                finalOutputFolderPath += " (Wiederhergestellt)";
            }
        }
        
        std::cerr << "DEBUG: Output folder path: " << finalOutputFolderPath << std::endl;
        
        // Lese die Anzahl der Dateien
        uint32_t fileCount;
        inputFile.read(reinterpret_cast<char*>(&fileCount), sizeof(fileCount));
        if (!inputFile) {
            lastError = "Fehler beim Lesen der Dateianzahl";
            return false;
        }
        
        std::cerr << "DEBUG: File count: " << fileCount << std::endl;
        
        // Erstelle den Ausgabeordner, falls er nicht existiert
        std::filesystem::create_directories(finalOutputFolderPath);
        
        // Entschlüssele jede Datei im Ordner
        for (uint32_t fileIndex = 0; fileIndex < fileCount; fileIndex++) {
            // Warte auf den Beginn eines Dateieintrags
            bool foundFileEntry = false;
            
            while (inputFile && !foundFileEntry) {
                char entryTag;
                inputFile.get(entryTag);
                
                if (!inputFile) {
                    break;
                }
                
                if (entryTag == HEADER_TAG_FILE_ENTRY) {
                    foundFileEntry = true;
                }
            }
            
            if (!foundFileEntry) {
                lastError = "Fehler beim Lesen des Dateieintrags";
                return false;
            }
            
            std::cerr << "DEBUG: Processing file " << (fileIndex + 1) << "/" << fileCount << std::endl;
            
            // Leseposition für den Dateieintrag merken
            std::vector<uint8_t> encryptedPath;
            std::vector<uint8_t> fileAuthTag;
            size_t fileSize = 0;
            
            // Lese die Dateiattribute
            while (inputFile) {
                char attributeTag;
                inputFile.get(attributeTag);
                
                if (!inputFile) {
                    lastError = "Fehler beim Lesen der Dateiattribute";
                    return false;
                }
                
                // Prüfe auf den Beginn eines neuen Dateieintrags oder das Ende der Datei
                if (attributeTag == HEADER_TAG_FILE_ENTRY || attributeTag == 0 || attributeTag >= 0x80) {
                    inputFile.seekg(-1, std::ios::cur); // Ein Zeichen zurück
                    break;
                }
                
                switch (attributeTag) {
                    case HEADER_TAG_FILE_PATH: {
                        uint16_t pathSize;
                        inputFile.read(reinterpret_cast<char*>(&pathSize), sizeof(pathSize));
                        if (!inputFile) {
                            lastError = "Fehler beim Lesen der Pfadgröße";
                            return false;
                        }
                        
                        encryptedPath.resize(pathSize);
                        inputFile.read(reinterpret_cast<char*>(encryptedPath.data()), pathSize);
                        if (!inputFile) {
                            lastError = "Fehler beim Lesen des verschlüsselten Pfads";
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
                        
                        fileAuthTag.resize(authTagSize);
                        inputFile.read(reinterpret_cast<char*>(fileAuthTag.data()), authTagSize);
                        if (!inputFile) {
                            lastError = "Fehler beim Lesen des Auth-Tags";
                            return false;
                        }
                        
                        // Setze den Auth-Tag für die nächste Entschlüsselung
                        params.authTag = fileAuthTag;
                        break;
                    }
                    
                    case HEADER_TAG_FILE_SIZE: {
                        inputFile.read(reinterpret_cast<char*>(&fileSize), sizeof(fileSize));
                        if (!inputFile) {
                            lastError = "Fehler beim Lesen der Dateigröße";
                            return false;
                        }
                        break;
                    }
                    
                    case HEADER_TAG_FILE_DATA: {
                        uint32_t encryptedSize;
                        inputFile.read(reinterpret_cast<char*>(&encryptedSize), sizeof(encryptedSize));
                        if (!inputFile) {
                            lastError = "Fehler beim Lesen der verschlüsselten Datengröße";
                            return false;
                        }
                        
                        // Lese die verschlüsselten Daten
                        std::vector<uint8_t> encryptedData(encryptedSize);
                        inputFile.read(reinterpret_cast<char*>(encryptedData.data()), encryptedSize);
                        if (!inputFile) {
                            lastError = "Fehler beim Lesen der verschlüsselten Daten";
                            return false;
                        }
                        
                        // Entschlüssele den Dateipfad
                        std::vector<uint8_t> decryptedPathBytes;
                        if (!decryptAES(encryptedPath, decryptedPathBytes, params, level)) {
                            lastError = "Fehler beim Entschlüsseln des Dateipfads";
                            return false;
                        }
                        
                        std::string decryptedPath(decryptedPathBytes.begin(), decryptedPathBytes.end());
                        
                        // Erstelle den vollständigen Pfad für die entschlüsselte Datei
                        std::string outputFilePath = finalOutputFolderPath + "/" + decryptedPath;
                        
                        std::cerr << "DEBUG: Decrypting file: " << decryptedPath << std::endl;
                        std::cerr << "DEBUG: Output path: " << outputFilePath << std::endl;
                        
                        // Erstelle das Verzeichnis für die Datei, falls es nicht existiert
                        std::filesystem::path parentPath = std::filesystem::path(outputFilePath).parent_path();
                        std::filesystem::create_directories(parentPath);
                        
                        // Entschlüssele die Daten
                        std::vector<uint8_t> decryptedData;
                        
                        // Für Sicherheitsstufe 5: Zuerst ChaCha20 entschlüsseln
                        if (level == SecurityLevel::LEVEL_5) {
                            std::vector<uint8_t> chacha20Decrypted;
                            if (!decryptChaCha20(encryptedData, chacha20Decrypted, params)) {
                                lastError = "Fehler beim Entschlüsseln mit ChaCha20";
                                return false;
                            }
                            encryptedData = std::move(chacha20Decrypted);
                        }
                        
                        // AES entschlüsseln
                        if (!decryptAES(encryptedData, decryptedData, params, level)) {
                            lastError = "Fehler beim Entschlüsseln. Falsches Passwort oder beschädigte Datei?";
                            return false;
                        }
                        
                        // Schreibe die entschlüsselte Datei
                        std::ofstream outputFile(outputFilePath, std::ios::binary);
                        if (!outputFile) {
                            lastError = "Fehler beim Erstellen der Ausgabedatei: " + outputFilePath;
                            return false;
                        }
                        
                        outputFile.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
                        
                        if (!outputFile) {
                            lastError = "Fehler beim Schreiben der entschlüsselten Daten";
                            return false;
                        }
                        
                        // Aktualisiere den Fortschritt
                        if (progressCallback) {
                            progressCallback(static_cast<float>(fileIndex + 1) / fileCount);
                        }
                        
                        break;
                    }
                    
                    default:
                        // Unbekanntes Attribut überspringen
                        char unknownSize;
                        inputFile.get(unknownSize);
                        if (!inputFile) {
                            lastError = "Fehler beim Lesen einer unbekannten Attributgröße";
                            return false;
                        }
                        
                        inputFile.seekg(unknownSize, std::ios::cur);
                        if (!inputFile) {
                            lastError = "Fehler beim Überspringen eines unbekannten Attributs";
                            return false;
                        }
                        break;
                }
            }
        }
        
        // Abschließender Fortschritt
        if (progressCallback) {
            progressCallback(1.0f);
        }
        
        std::cerr << "DEBUG: Folder decryption completed successfully" << std::endl;
        return true;
    } catch (const std::exception& e) {
        lastError = "Fehler bei der Ordnerentschlüsselung: ";
        lastError += e.what();
        return false;
    }
}

} // namespace encrypt