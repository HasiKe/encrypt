<p align="center">
  <img src="docs/assets/logo.svg" alt="Encrypt Logo" width="120" height="120">
</p>

<h1 align="center">🔐 Encrypt</h1>

<p align="center">
  <strong>Sichere Datei- und Ordnerverschlüsselung mit militärischer Stärke</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#verwendung">Verwendung</a> •
  <a href="#sicherheit">Sicherheit</a> •
  <a href="README_EN.md">English</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/C++-17-00599C?style=flat-square&logo=cplusplus" alt="C++17">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Encryption-AES--256%20%7C%20ChaCha20-red?style=flat-square" alt="Encryption">
</p>

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🛡️ Sicherheit
- **5 Sicherheitsstufen** von schnell bis maximal
- **AES-256-GCM** Authenticated Encryption
- **ChaCha20** Double-Encryption (Stufe 5)
- **Argon2id** Memory-Hard KDF
- **Manipulationsschutz** durch Auth-Tags

</td>
<td width="50%">

### 🚀 Benutzerfreundlichkeit
- **Drag & Drop** unter Windows
- **CLI** für alle Plattformen
- **Ordner-Verschlüsselung** mit einem Klick
- **Passwort-Stärkeprüfung** in Echtzeit
- **Fortschrittsanzeige** bei großen Dateien

</td>
</tr>
</table>

---

## 📊 Sicherheitsstufen

| Stufe | Cipher | KDF | Parameter | Anwendungsfall |
|:-----:|--------|-----|-----------|----------------|
| **1** | AES-128-GCM | PBKDF2 | 10K Iterationen | Schnelle Verschlüsselung |
| **2** | AES-256-GCM | PBKDF2 | 100K Iterationen | **Empfohlen** ⭐ |
| **3** | AES-256-GCM | PBKDF2 | 250K Iterationen | Sensible Daten |
| **4** | AES-256-GCM | Argon2id | 64 MB RAM | Hohe Sicherheit |
| **5** | AES-256 + ChaCha20 | Argon2id | 256 MB RAM | Maximale Sicherheit |

---

## 📦 Installation

### Voraussetzungen

```bash
# Ubuntu/Debian
sudo apt install build-essential cmake libssl-dev

# Optional für maximale Sicherheit
sudo apt install libsodium-dev libargon2-dev

# Für Windows Cross-Compile
sudo apt install mingw-w64
```

### Kompilieren

<details>
<summary><b>🐧 Linux</b></summary>

```bash
git clone https://github.com/HasiKe/encrypt.git
cd encrypt
mkdir build && cd build
cmake ..
make -j$(nproc)

# Optional: Systemweit installieren
sudo make install
```

</details>

<details>
<summary><b>🪟 Windows (Cross-Compile)</b></summary>

```bash
./build_windows.sh
# oder manuell:
mkdir build_windows && cd build_windows
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-mingw-w64.cmake ..
make -j$(nproc)
```

Die fertige `encrypt.exe` liegt in `build_windows/install/`.

</details>

<details>
<summary><b>🏗️ Arch Linux (AUR)</b></summary>

```bash
yay -S encrypt-git
```

</details>

---

## 🎯 Verwendung

### Kommandozeile (CLI)

```bash
# Datei verschlüsseln (Standard: Stufe 2)
encrypt dokument.pdf

# Mit höherer Sicherheit
encrypt -l 4 geheim.docx

# Ordner verschlüsseln
encrypt projekte/

# Entschlüsseln
encrypt -d dokument.pdf.cryp

# Passwort-Stärke prüfen
encrypt -c
```

### Windows Drag & Drop

1. **Starten** Sie `encrypt.exe`
2. **Ziehen** Sie Dateien/Ordner in das Fenster
3. **Geben** Sie Ihr Passwort ein
4. **Wählen** Sie die Sicherheitsstufe
5. ✅ **Fertig!**

### Alle Optionen

```
encrypt [Optionen] <Datei/Ordner>

Optionen:
  -h, --help              Hilfe anzeigen
  -d, --decrypt           Entschlüsseln (Standard: verschlüsseln)
  -o, --output <Pfad>     Ausgabepfad angeben
  -p, --password <Pass>   Passwort (⚠️ unsicher!)
  -l, --level <1-5>       Sicherheitsstufe
  -c, --check-password    Passwort-Checker starten
```

---

## 🔒 Sicherheit

### Dateiformat

```
┌─────────────────────────────────────────────┐
│  Header                                     │
│  ├── Signatur: "SECF" (4 Bytes)            │
│  ├── Version: 0x01                          │
│  ├── Sicherheitsstufe                       │
│  ├── Salt (32 Bytes)                        │
│  ├── IV (16-28 Bytes)                       │
│  ├── Verschlüsselter Dateiname              │
│  └── Auth-Tag (16 Bytes)                    │
├─────────────────────────────────────────────┤
│  Verschlüsselte Daten (Chunks à 64 KB)     │
│  └── Jeder Chunk mit eigenem Auth-Tag       │
└─────────────────────────────────────────────┘
```

### Best Practices

> ⚠️ **Wichtig**: Verschlüsselung ist nur so stark wie Ihr Passwort!

- ✅ Mindestens **12 Zeichen**
- ✅ Groß- und Kleinbuchstaben, Zahlen, Sonderzeichen
- ✅ Verwenden Sie einen **Passwort-Manager**
- ❌ Keine Wörter aus dem Wörterbuch
- ❌ Keine persönlichen Informationen

---

## 🏗️ Projektstruktur

```
encrypt/
├── 📁 include/encrypt/      # Header-Dateien
│   ├── crypto.h             # Kryptographie-API
│   └── platform.h           # Plattform-Abstraktion
├── 📁 src/
│   ├── 📁 core/             # Kern-Implementierung
│   │   └── crypto.cpp       # Verschlüsselungslogik
│   ├── 📁 platform/         # Plattform-spezifisch
│   │   ├── linux.cpp
│   │   └── windows.cpp
│   ├── 📁 ui/               # Benutzeroberfläche
│   │   └── cli.cpp
│   └── main.cpp
├── 📁 lib/                   # Abhängigkeiten
├── 📁 resources/             # Windows-Ressourcen
├── 📁 docs/                  # Dokumentation
├── 📁 test/                  # Unit-Tests
├── CMakeLists.txt
└── README.md
```

---

## 🤝 Beitragen

Beiträge sind willkommen! Bitte lesen Sie [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
# Fork & Clone
git clone https://github.com/YOUR_USERNAME/encrypt.git

# Branch erstellen
git checkout -b feature/mein-feature

# Änderungen committen
git commit -m "feat: Beschreibung"

# Pull Request erstellen
```

---

## 📄 Lizenz

Dieses Projekt steht unter der **MIT-Lizenz** - siehe [LICENSE](LICENSE).

---

## 🙏 Danksagungen

- [OpenSSL](https://www.openssl.org/) - Kryptographie-Bibliothek
- [libsodium](https://libsodium.org/) - ChaCha20-Implementierung
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) - Memory-Hard KDF

---

<p align="center">
  <sub>Made with ❤️ by <a href="https://github.com/HasiKe">HasiKe</a></sub>
</p>
