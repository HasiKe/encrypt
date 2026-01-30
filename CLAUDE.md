# 🛠️ Encrypt - Entwickler-Leitfaden

> Schnellreferenz für Entwicklung und Erweiterung des Projekts.

---

## ⚡ Quick Start

```bash
# Abhängigkeiten (Ubuntu/Debian)
sudo apt install build-essential cmake libssl-dev libsodium-dev

# Linux-Build
mkdir build && cd build && cmake .. && make -j$(nproc)

# Windows Cross-Compile
./build_windows.sh

# Tests
cmake -DBUILD_TESTS=ON .. && make && ctest --verbose
```

---

## 📁 Projektstruktur

```
encrypt/
├── include/encrypt/     # Öffentliche Header
│   ├── crypto.h         # Kern-API
│   └── platform.h       # Plattform-Abstraktion
├── src/
│   ├── core/            # Kryptographie-Implementierung
│   │   └── crypto.cpp   # ~1000 Zeilen
│   ├── platform/        # Plattform-spezifischer Code
│   │   ├── linux.cpp    # Linux-UI & Dateisystem
│   │   └── windows.cpp  # Win32-UI, Drag&Drop
│   ├── ui/              # Benutzeroberfläche
│   │   └── cli.cpp      # Kommandozeilen-Interface
│   └── main.cpp         # Entry Point
├── lib/argon2/          # Argon2 Fallback
├── resources/           # Windows-Ressourcen
├── test/                # Unit-Tests
└── cmake/               # CMake Toolchains
```

---

## 🎨 Code-Stil

### Namenskonventionen

```cpp
namespace encrypt {           // Namespace: snake_case

class Crypto {                // Klassen: PascalCase
public:
    static bool encryptFile();    // Methoden: camelCase
    
private:
    std::string lastError;        // Member: camelCase
};

namespace crypto_constants {
    constexpr size_t SALT_SIZE = 32;  // Konstanten: UPPER_CASE
}

} // namespace encrypt
```

### Formatierung

- **Einrückung:** 4 Spaces (keine Tabs)
- **Zeilenlänge:** Max. 100 Zeichen
- **Klammern:** K&R Style
- **Includes:** System → Externe → Projekt

```cpp
#include <iostream>           // System
#include <openssl/evp.h>      // Externe
#include "encrypt/crypto.h"   // Projekt
```

### Dokumentation

```cpp
/**
 * @brief Verschlüsselt eine Datei mit AES-GCM
 * 
 * @param inputFileName  Pfad zur Quelldatei
 * @param outputFileName Pfad zur Zieldatei
 * @param password       Benutzer-Passwort
 * @param level          Sicherheitsstufe (1-5)
 * @return true bei Erfolg, false bei Fehler
 * 
 * @note Verwendet intern PBKDF2 oder Argon2id für KDF
 * @see decryptFile() für Entschlüsselung
 */
static bool encryptFile(...);
```

---

## 🔧 Erweiterungen

### Neuen Algorithmus hinzufügen

1. **Header erweitern** (`include/encrypt/crypto.h`):
```cpp
// Neue private Methode
static bool encryptNewAlgo(
    const std::vector<uint8_t>& input, 
    std::vector<uint8_t>& output,
    const CryptoParams& params
);
```

2. **Implementierung** (`src/core/crypto.cpp`):
```cpp
bool Crypto::encryptNewAlgo(...) {
    // Implementation
}
```

3. **In encryptFile() integrieren**:
```cpp
if (level == SecurityLevel::LEVEL_NEW) {
    if (!encryptNewAlgo(data, output, params)) {
        return false;
    }
}
```

### Neue Plattform hinzufügen

1. **Datei erstellen**: `src/platform/macos.cpp`

2. **Platform-Namespace implementieren**:
```cpp
#ifdef __APPLE__

namespace encrypt {
namespace platform {
    void showMessage(...) { /* macOS Dialog */ }
    std::string getPassword(...) { /* macOS Keychain? */ }
    // ...
}
}

#endif // __APPLE__
```

3. **CMakeLists.txt erweitern**:
```cmake
if(APPLE)
    set(PLATFORM_SOURCES src/platform/macos.cpp)
    # Link Cocoa/AppKit frameworks
endif()
```

### Neue CLI-Option hinzufügen

1. **In `src/ui/cli.cpp`** Argument parsen:
```cpp
} else if ((arg == "-n" || arg == "--new-option") && i + 1 < argc) {
    newOptionValue = argv[++i];
}
```

2. **Hilfe aktualisieren**:
```cpp
void printHelp() {
    // ...
    std::cout << "  -n, --new-option      Beschreibung" << std::endl;
}
```

---

## 🧪 Testing

### Test ausführen

```bash
# Alle Tests
cd build && ctest --verbose

# Einzelner Test
./bin/crypto_test

# Mit Valgrind (Memory Leaks)
valgrind --leak-check=full ./bin/crypto_test
```

### Test hinzufügen

```cpp
// test/crypto_test.cpp
failedTests += !runTest("Mein neuer Test", []() {
    // Setup
    createTestFile("test.txt", "Inhalt");
    
    // Aktion
    bool result = encrypt::Crypto::encryptFile(
        "test.txt", "test.cryp", "password"
    );
    
    // Aufräumen
    std::remove("test.txt");
    std::remove("test.cryp");
    
    return result;
});
```

---

## 🔐 Sicherheitshinweise

### DO ✅

- Sichere Zufallszahlen: `RAND_bytes()` oder `simple_crypto::random_bytes()`
- Konstante-Zeit-Vergleiche für kryptographische Werte
- Speicher nach Gebrauch überschreiben (sensible Daten)
- Auth-Tags IMMER prüfen vor Entschlüsselung

### DON'T ❌

- Niemals `rand()` für Kryptographie
- Keine hartkodierten Schlüssel/IVs
- Keine Passwörter in Logs
- Keine eigenen Krypto-Algorithmen erfinden

---

## 📦 Release-Checkliste

- [ ] Version in CMakeLists.txt aktualisieren
- [ ] CHANGELOG.md aktualisieren
- [ ] Tests erfolgreich
- [ ] Linux-Build funktioniert
- [ ] Windows-Build funktioniert
- [ ] README aktuell
- [ ] Git Tag erstellen: `git tag -a v1.0.0 -m "Release 1.0.0"`

---

## 🐛 Debugging

### Debug-Build

```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

### Wichtige Debug-Ausgaben

```cpp
std::cerr << "DEBUG: Key size: " << params.key.size() << std::endl;
std::cerr << "DEBUG: IV size: " << params.iv.size() << std::endl;
```

### GDB verwenden

```bash
gdb ./bin/encrypt
(gdb) break Crypto::encryptFile
(gdb) run test.txt
(gdb) print params.key.size()
```

---

## 📞 Kontakt

- **Issues:** [GitHub Issues](https://github.com/HasiKe/encrypt/issues)
- **Pull Requests:** Immer willkommen!

---

<p align="center">
  <sub>Happy Coding! 🚀</sub>
</p>
