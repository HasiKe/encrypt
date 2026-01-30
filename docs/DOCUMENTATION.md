# 📖 Encrypt - Technische Dokumentation

## Inhaltsverzeichnis

1. [Architektur](#architektur)
2. [Kryptographische Details](#kryptographische-details)
3. [Dateiformat](#dateiformat)
4. [API-Referenz](#api-referenz)
5. [Build-System](#build-system)
6. [Sicherheitsanalyse](#sicherheitsanalyse)
7. [Fehlerbehebung](#fehlerbehebung)

---

## Architektur

### Systemübersicht

```
┌─────────────────────────────────────────────────────────────────┐
│                         Anwendung                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │  CLI (ui/)  │    │  GUI (Win)  │    │  API        │         │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘         │
│         │                  │                  │                 │
│         └──────────────────┼──────────────────┘                 │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Platform Abstraction Layer                  │   │
│  │                    (platform.h)                          │   │
│  └──────────────────────────┬──────────────────────────────┘   │
│                             ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Crypto Core                           │   │
│  │                    (crypto.h)                            │   │
│  ├─────────────────────────────────────────────────────────┤   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐        │   │
│  │  │  AES-GCM   │  │  ChaCha20  │  │  Key       │        │   │
│  │  │  Engine    │  │  Engine    │  │  Derivation│        │   │
│  │  └────────────┘  └────────────┘  └────────────┘        │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Kryptographie-Backend                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   OpenSSL    │  │  libsodium   │  │   Argon2     │          │
│  │   (Linux)    │  │  (optional)  │  │  (optional)  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

### Datenfluss

```
                    Verschlüsselung
                    ──────────────►

┌─────────┐    ┌──────────┐    ┌──────────┐    ┌─────────┐
│ Klartext│───►│   KDF    │───►│  AES-GCM │───►│ Cipher- │
│  Datei  │    │(Password)│    │(+ChaCha20│    │  text   │
└─────────┘    └──────────┘    │  Lvl 5)  │    └─────────┘
                    │          └──────────┘
                    │               │
                    ▼               ▼
              ┌──────────┐    ┌──────────┐
              │   Salt   │    │ Auth-Tag │
              │   IV     │    │          │
              └──────────┘    └──────────┘

                    Entschlüsselung
                    ◄──────────────
```

---

## Kryptographische Details

### Schlüsselableitung (KDF)

#### PBKDF2-HMAC-SHA512 (Stufen 1-3)

```cpp
// Parameter pro Stufe
struct PBKDF2Params {
    int iterations;
    size_t keySize;
};

const PBKDF2Params PBKDF2_PARAMS[] = {
    {10000,   16},  // Level 1: AES-128
    {100000,  32},  // Level 2: AES-256
    {250000,  32},  // Level 3: AES-256
};
```

**Algorithmus:**
```
DK = PBKDF2(HMAC-SHA512, Password, Salt, Iterations, KeyLength)
```

#### Argon2id (Stufen 4-5)

```cpp
// Parameter pro Stufe
struct Argon2Params {
    uint32_t timeCost;      // Iterationen
    uint32_t memoryCost;    // KB RAM
    uint32_t parallelism;   // Threads
};

const Argon2Params ARGON2_PARAMS[] = {
    {3,  65536,  4},  // Level 4: 64 MB
    {4, 262144,  8},  // Level 5: 256 MB
};
```

**Algorithmus:**
```
DK = Argon2id(Password, Salt, TimeCost, MemoryCost, Parallelism, KeyLength)
```

### Verschlüsselungsalgorithmen

#### AES-GCM

- **Modus:** Galois/Counter Mode (GCM)
- **Schlüsselgrößen:** 128-bit (Stufe 1), 256-bit (Stufen 2-5)
- **IV-Größe:** 96-bit (12 Bytes) oder 128-bit (16 Bytes)
- **Tag-Größe:** 128-bit (16 Bytes)

```cpp
// Verschlüsselung
bool encryptAES(input, output, key, iv, &authTag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    EVP_EncryptUpdate(ctx, output, &outlen, input, inlen);
    EVP_EncryptFinal_ex(ctx, output + outlen, &finallen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, authTag);
    return true;
}
```

#### ChaCha20 (Stufe 5)

Zweite Verschlüsselungsschicht für maximale Sicherheit:

```cpp
// Double Encryption (Level 5)
AES_Output = AES-256-GCM(Plaintext, Key1, IV1)
Final_Output = ChaCha20(AES_Output, Key2, Nonce)
```

- **Schlüsselgröße:** 256-bit
- **Nonce-Größe:** 96-bit (12 Bytes)

---

## Dateiformat

### Header-Struktur (TLV-Format)

```
Offset  Größe   Feld                    Beschreibung
──────────────────────────────────────────────────────────────
0x00    4       Signatur                "SECF" (0x53454346)
0x04    1       Version                 0x01
0x05    1       Tag: Security Level     0x01
0x06    1       Security Level          1-5
0x07    1       Tag: Salt               0x02
0x08    1       Salt Length             32
0x09    32      Salt                    Zufällige Bytes
0x29    1       Tag: IV                 0x03
0x2A    1       IV Length               16 oder 28 (Lvl 5)
0x2B    var     IV                      Initialisierungsvektor
...     1       Tag: Filename           0x05
...     2       Filename Length         Little-Endian
...     var     Encrypted Filename      AES-verschlüsselt
...     1       Tag: Auth Tag           0x04
...     1       Auth Tag Length         16
...     16      Auth Tag                GCM Authentication Tag
...     1       End Marker              0x00
──────────────────────────────────────────────────────────────
        var     Encrypted Data          Chunks à 64 KB + Tag
```

### Tag-Definitionen

| Tag | Hex | Beschreibung |
|-----|-----|--------------|
| SECURITY_LEVEL | 0x01 | Sicherheitsstufe (1-5) |
| SALT | 0x02 | Kryptographisches Salt |
| IV | 0x03 | Initialisierungsvektor |
| AUTH_TAG | 0x04 | GCM Authentication Tag |
| FILENAME | 0x05 | Verschlüsselter Dateiname |
| CHACHA_NONCE | 0x06 | ChaCha20 Nonce (Stufe 5) |
| FOLDER | 0x07 | Ordner-Marker |
| FILE_ENTRY | 0x08 | Dateieintrag in Ordner |
| FILE_PATH | 0x09 | Relativer Pfad |
| FILE_SIZE | 0x0A | Originalgröße |
| FILE_DATA | 0x0B | Verschlüsselte Daten |

### Ordnerformat

```
Header (wie oben)
├── FOLDER Tag (0x07)
├── Folder Version (0x01)
├── Encrypted Folder Name
├── File Count (uint32)
└── File Entries[]
    ├── FILE_ENTRY Tag (0x08)
    ├── FILE_PATH Tag + Encrypted Path
    ├── FILE_SIZE Tag + Original Size
    ├── FILE_DATA Tag + Encrypted Content
    └── AUTH_TAG for this file
```

---

## API-Referenz

### Klasse: `Crypto`

#### Datei-Operationen

```cpp
// Datei verschlüsseln
static bool encryptFile(
    const std::string& inputFileName, 
    const std::string& outputFileName, 
    const std::string& password,
    SecurityLevel level = SecurityLevel::LEVEL_2,
    const std::function<void(float)>& progressCallback = nullptr
);

// Datei entschlüsseln
static bool decryptFile(
    const std::string& inputFileName, 
    const std::string& password,
    const std::string& outputFileName = "",
    const std::function<void(float)>& progressCallback = nullptr
);
```

#### Ordner-Operationen

```cpp
// Ordner verschlüsseln
static bool encryptFolder(
    const std::string& inputFolderPath,
    const std::string& outputFileName,
    const std::string& password,
    SecurityLevel level = SecurityLevel::LEVEL_2,
    const std::function<void(float)>& progressCallback = nullptr
);

// Ordner entschlüsseln
static bool decryptFolder(
    const std::string& inputFileName,
    const std::string& password,
    const std::string& outputFolderPath = "",
    const std::function<void(float)>& progressCallback = nullptr
);
```

#### Utilities

```cpp
// Passwort-Stärke prüfen (0-100)
static int checkPasswordStrength(const std::string& password);

// Letzte Fehlermeldung abrufen
static std::string getLastError();

// Verschlüsselung testen
static bool testEncryption(
    const std::string& testString, 
    const std::string& password, 
    SecurityLevel level
);
```

### Enum: `SecurityLevel`

```cpp
enum class SecurityLevel {
    LEVEL_1 = 1,  // AES-128-GCM, PBKDF2 10K
    LEVEL_2 = 2,  // AES-256-GCM, PBKDF2 100K (Standard)
    LEVEL_3 = 3,  // AES-256-GCM, PBKDF2 250K
    LEVEL_4 = 4,  // AES-256-GCM, Argon2id 64MB
    LEVEL_5 = 5   // AES-256 + ChaCha20, Argon2id 256MB
};
```

### Namespace: `platform`

```cpp
namespace platform {
    // Benutzer-Interaktion
    void showMessage(const std::string& message, const std::string& title);
    std::string getPassword(const std::string& prompt = "...");
    std::string getPasswordWithConfirmation();
    SecurityLevel getSecurityLevel();
    
    // Fortschrittsanzeige
    void updateProgress(float progress, const std::string& operation);
    
    // Dateisystem
    std::string normalizePath(const std::string& path);
    std::string getFileName(const std::string& path);
    bool fileExists(const std::string& path);
    bool isFolder(const std::string& path);
    bool isEncryptedFile(const std::string& path);
    
    // High-Level
    bool processFile(const std::string& filePath);
}
```

---

## Build-System

### CMake-Optionen

| Option | Standard | Beschreibung |
|--------|----------|--------------|
| `BUILD_WINDOWS` | OFF | Windows Cross-Compile aktivieren |
| `BUILD_TESTS` | OFF | Unit-Tests bauen |
| `USE_SYSTEM_LIBSODIUM` | ON | System-libsodium verwenden |

### Abhängigkeiten

```cmake
# Erforderlich
find_package(OpenSSL REQUIRED)  # AES-GCM, PBKDF2
find_package(Threads REQUIRED)  # Multi-Threading

# Optional
find_library(SODIUM_LIBRARY sodium)  # ChaCha20
find_library(ARGON2_LIBRARY argon2)  # Argon2id
```

### Build-Targets

| Target | Beschreibung |
|--------|--------------|
| `encrypt_core` | Statische Bibliothek mit Kern-Funktionen |
| `encrypt_linux` | Linux-Executable |
| `encrypt_windows` | Windows-Executable (Cross-Compile) |
| `encrypt_native` | Windows-Executable (Native) |

---

## Sicherheitsanalyse

### Bedrohungsmodell

| Bedrohung | Schutz | Implementierung |
|-----------|--------|-----------------|
| Brute-Force | KDF mit hohen Kosten | PBKDF2/Argon2id |
| Dictionary-Attack | Salt pro Datei | 32-Byte Salt |
| Side-Channel | Konstante Zeit | OpenSSL-Implementierung |
| Bit-Flipping | Auth. Encryption | AES-GCM Tags |
| Replay-Attack | Unique IV | Zufälliger IV pro Datei |

### Kryptographische Stärke

| Stufe | Effektive Bits | Empfehlung |
|-------|----------------|------------|
| 1 | ~128 bit | Kurzzeit-Speicherung |
| 2 | ~180 bit | Allgemeiner Gebrauch |
| 3 | ~200 bit | Sensible Daten |
| 4 | ~220 bit | Langzeit-Archivierung |
| 5 | ~256 bit | Hochsicherheit |

---

## Fehlerbehebung

### Häufige Fehler

#### "Ungültiges Dateiformat"
- Datei ist keine `.cryp`-Datei
- Datei wurde beschädigt
- Header wurde manipuliert

#### "Authentizitätsprüfung fehlgeschlagen"
- Falsches Passwort
- Datei wurde verändert
- Korrupte Daten

#### "Fehler bei Schlüsselableitung"
- Nicht genug Arbeitsspeicher (Stufe 4/5)
- Leeres Passwort
- Fehlerhafte libargon2

### Debug-Modus

```bash
# Mit Debug-Ausgaben kompilieren
cmake -DCMAKE_BUILD_TYPE=Debug ..
make

# Ausführen mit stderr-Ausgabe
./encrypt datei.txt 2> debug.log
```

### Speicheranforderungen

| Stufe | Minimum RAM |
|-------|-------------|
| 1-3 | ~10 MB |
| 4 | ~100 MB |
| 5 | ~300 MB |

---

<p align="center">
  <sub>Dokumentation für Encrypt v1.0.0</sub>
</p>
