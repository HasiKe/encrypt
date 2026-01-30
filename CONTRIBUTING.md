# Mitwirken / Contributing

[🇩🇪 Deutsch](#deutsch) | [🇬🇧 English](#english)

---

## Deutsch

Vielen Dank für dein Interesse, zu **Encrypt** beizutragen! Dieses Projekt lebt von der Community und jede Hilfe ist willkommen.

### Wie du helfen kannst

#### 🐛 Bugs melden

1. Überprüfe zunächst, ob der Bug bereits gemeldet wurde (siehe [Issues](../../issues))
2. Erstelle ein neues Issue mit:
   - Klare Beschreibung des Problems
   - Schritte zur Reproduktion
   - Erwartetes vs. tatsächliches Verhalten
   - Betriebssystem und Version
   - Encrypt-Version (`encrypt -v`)

#### 💡 Feature-Vorschläge

1. Öffne ein Issue mit dem Label `enhancement`
2. Beschreibe das gewünschte Feature detailliert
3. Erkläre den Anwendungsfall und warum es nützlich wäre

#### 🔧 Code-Beiträge

##### Vorbereitung

1. Fork das Repository
2. Clone deinen Fork:
   ```bash
   git clone https://github.com/DEIN-USERNAME/encrypt.git
   cd encrypt
   ```
3. Erstelle einen Feature-Branch:
   ```bash
   git checkout -b feature/mein-feature
   ```

##### Entwicklungsumgebung

**Voraussetzungen:**
- CMake 3.12+
- C++17 Compiler (GCC 8+, Clang 7+, MSVC 2019+)
- OpenSSL 1.1+ (Linux/macOS)
- MinGW-w64 (für Windows Cross-Compile)

**Build:**
```bash
mkdir build && cd build
cmake .. -DBUILD_TESTS=ON
make -j$(nproc)
ctest --verbose
```

##### Code-Richtlinien

- **Sprache:** C++17 Standard
- **Formatierung:** 4 Spaces Einrückung, keine Tabs
- **Namenskonventionen:**
  - Klassen: `PascalCase`
  - Funktionen/Methoden: `camelCase`
  - Konstanten: `UPPER_SNAKE_CASE`
  - Variablen: `camelCase`
- **Kommentare:** Doxygen-Format für öffentliche APIs
- **Tests:** Für neue Features müssen Tests geschrieben werden

##### Commit-Messages

Verwende aussagekräftige Commit-Messages im Format:
```
<typ>(<bereich>): <kurze beschreibung>

[optionaler body]
```

**Typen:**
- `feat`: Neues Feature
- `fix`: Bugfix
- `docs`: Dokumentation
- `refactor`: Code-Umstrukturierung
- `test`: Tests
- `chore`: Wartungsarbeiten

**Beispiele:**
```
feat(crypto): Implementiere ChaCha20-Poly1305 Verschlüsselung
fix(cli): Korrigiere Fortschrittsanzeige bei großen Dateien
docs(readme): Aktualisiere Installationsanleitung
```

##### Pull Request erstellen

1. Pushe deinen Branch:
   ```bash
   git push origin feature/mein-feature
   ```
2. Erstelle einen Pull Request auf GitHub
3. Beschreibe deine Änderungen detailliert
4. Verlinke relevante Issues

### Code of Conduct

- Respektvoller Umgang miteinander
- Konstruktive Kritik willkommen
- Keine Diskriminierung jeglicher Art
- Fokus auf die Sache, nicht die Person

---

## English

Thank you for your interest in contributing to **Encrypt**! This project thrives on community involvement, and all help is welcome.

### How to help

#### 🐛 Reporting Bugs

1. First check if the bug has already been reported (see [Issues](../../issues))
2. Create a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs. actual behavior
   - Operating system and version
   - Encrypt version (`encrypt -v`)

#### 💡 Feature Suggestions

1. Open an issue with the `enhancement` label
2. Describe the desired feature in detail
3. Explain the use case and why it would be useful

#### 🔧 Code Contributions

##### Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/encrypt.git
   cd encrypt
   ```
3. Create a feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```

##### Development Environment

**Prerequisites:**
- CMake 3.12+
- C++17 Compiler (GCC 8+, Clang 7+, MSVC 2019+)
- OpenSSL 1.1+ (Linux/macOS)
- MinGW-w64 (for Windows cross-compile)

**Build:**
```bash
mkdir build && cd build
cmake .. -DBUILD_TESTS=ON
make -j$(nproc)
ctest --verbose
```

##### Coding Guidelines

- **Language:** C++17 standard
- **Formatting:** 4 spaces indentation, no tabs
- **Naming conventions:**
  - Classes: `PascalCase`
  - Functions/Methods: `camelCase`
  - Constants: `UPPER_SNAKE_CASE`
  - Variables: `camelCase`
- **Comments:** Doxygen format for public APIs
- **Tests:** Tests must be written for new features

##### Commit Messages

Use meaningful commit messages in the format:
```
<type>(<scope>): <short description>

[optional body]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code restructuring
- `test`: Tests
- `chore`: Maintenance

**Examples:**
```
feat(crypto): Implement ChaCha20-Poly1305 encryption
fix(cli): Fix progress display for large files
docs(readme): Update installation instructions
```

##### Creating a Pull Request

1. Push your branch:
   ```bash
   git push origin feature/my-feature
   ```
2. Create a pull request on GitHub
3. Describe your changes in detail
4. Link relevant issues

### Code of Conduct

- Treat each other with respect
- Constructive criticism is welcome
- No discrimination of any kind
- Focus on the matter, not the person

---

## Lizenz / License

Durch das Einreichen von Beiträgen stimmst du zu, dass diese unter der [MIT-Lizenz](LICENSE) veröffentlicht werden.

By submitting contributions, you agree that they will be published under the [MIT License](LICENSE).
