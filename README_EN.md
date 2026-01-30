<p align="center">
  <img src="docs/assets/logo.svg" alt="Encrypt Logo" width="120" height="120">
</p>

<h1 align="center">🔐 Encrypt</h1>

<p align="center">
  <strong>Military-grade file and folder encryption made simple</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#security">Security</a> •
  <a href="README.md">Deutsch</a>
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

### 🛡️ Security
- **5 Security Levels** from fast to maximum
- **AES-256-GCM** Authenticated Encryption
- **ChaCha20** Double-Encryption (Level 5)
- **Argon2id** Memory-Hard KDF
- **Tamper Protection** via Auth-Tags

</td>
<td width="50%">

### 🚀 Ease of Use
- **Drag & Drop** on Windows
- **CLI** for all platforms
- **Folder Encryption** with one click
- **Password Strength Check** in real-time
- **Progress Indicator** for large files

</td>
</tr>
</table>

---

## 📊 Security Levels

| Level | Cipher | KDF | Parameters | Use Case |
|:-----:|--------|-----|-----------|----------|
| **1** | AES-128-GCM | PBKDF2 | 10K iterations | Fast encryption |
| **2** | AES-256-GCM | PBKDF2 | 100K iterations | **Recommended** ⭐ |
| **3** | AES-256-GCM | PBKDF2 | 250K iterations | Sensitive data |
| **4** | AES-256-GCM | Argon2id | 64 MB RAM | High security |
| **5** | AES-256 + ChaCha20 | Argon2id | 256 MB RAM | Maximum security |

---

## 📦 Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install build-essential cmake libssl-dev

# Optional for maximum security
sudo apt install libsodium-dev libargon2-dev

# For Windows Cross-Compile
sudo apt install mingw-w64
```

### Building

<details>
<summary><b>🐧 Linux</b></summary>

```bash
git clone https://github.com/HasiKe/encrypt.git
cd encrypt
mkdir build && cd build
cmake ..
make -j$(nproc)

# Optional: Install system-wide
sudo make install
```

</details>

<details>
<summary><b>🪟 Windows (Cross-Compile)</b></summary>

```bash
./build_windows.sh
# or manually:
mkdir build_windows && cd build_windows
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-mingw-w64.cmake ..
make -j$(nproc)
```

The finished `encrypt.exe` is located in `build_windows/install/`.

</details>

---

## 🎯 Usage

### Command Line (CLI)

```bash
# Encrypt a file (default: Level 2)
encrypt document.pdf

# With higher security
encrypt -l 4 secret.docx

# Encrypt a folder
encrypt projects/

# Decrypt
encrypt -d document.pdf.cryp

# Check password strength
encrypt -c
```

### Windows Drag & Drop

1. **Start** `encrypt.exe`
2. **Drag** files/folders into the window
3. **Enter** your password
4. **Select** the security level
5. ✅ **Done!**

### All Options

```
encrypt [options] <file/folder>

Options:
  -h, --help              Show help
  -d, --decrypt           Decrypt (default: encrypt)
  -o, --output <path>     Specify output path
  -p, --password <pass>   Password (⚠️ insecure!)
  -l, --level <1-5>       Security level
  -c, --check-password    Start password checker
```

---

## 🔒 Security

### File Format

```
┌─────────────────────────────────────────────┐
│  Header                                     │
│  ├── Signature: "SECF" (4 bytes)           │
│  ├── Version: 0x01                          │
│  ├── Security Level                         │
│  ├── Salt (32 bytes)                        │
│  ├── IV (16-28 bytes)                       │
│  ├── Encrypted Filename                     │
│  └── Auth-Tag (16 bytes)                    │
├─────────────────────────────────────────────┤
│  Encrypted Data (64 KB chunks)             │
│  └── Each chunk with its own Auth-Tag       │
└─────────────────────────────────────────────┘
```

### Best Practices

> ⚠️ **Important**: Encryption is only as strong as your password!

- ✅ At least **12 characters**
- ✅ Upper and lowercase, numbers, special characters
- ✅ Use a **password manager**
- ❌ No dictionary words
- ❌ No personal information

---

## 🏗️ Project Structure

```
encrypt/
├── 📁 include/encrypt/      # Header files
│   ├── crypto.h             # Cryptography API
│   └── platform.h           # Platform abstraction
├── 📁 src/
│   ├── 📁 core/             # Core implementation
│   │   └── crypto.cpp       # Encryption logic
│   ├── 📁 platform/         # Platform-specific
│   │   ├── linux.cpp
│   │   └── windows.cpp
│   ├── 📁 ui/               # User interface
│   │   └── cli.cpp
│   └── main.cpp
├── 📁 lib/                   # Dependencies
├── 📁 resources/             # Windows resources
├── 📁 docs/                  # Documentation
├── 📁 test/                  # Unit tests
├── CMakeLists.txt
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
# Fork & Clone
git clone https://github.com/YOUR_USERNAME/encrypt.git

# Create branch
git checkout -b feature/my-feature

# Commit changes
git commit -m "feat: Description"

# Create Pull Request
```

---

## 📄 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE).

---

## 🙏 Acknowledgments

- [OpenSSL](https://www.openssl.org/) - Cryptography library
- [libsodium](https://libsodium.org/) - ChaCha20 implementation
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) - Memory-Hard KDF

---

<p align="center">
  <sub>Made with ❤️ by <a href="https://github.com/HasiKe">HasiKe</a></sub>
</p>
