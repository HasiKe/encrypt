# EncryptionTool

Ein fortschrittliches Werkzeug zur sicheren Ver- und Entschlüsselung von Dateien für Linux und Windows mit mehreren Sicherheitsstufen.

## Funktionen

- Datenverschlüsselung mit wählbarer Sicherheitsstufe (1-5)
- Moderne Kryptographie mit AES-256-GCM und ChaCha20
- Starke Schlüsselableitung (PBKDF2, Argon2id)
- Authentifizierte Verschlüsselung zum Schutz vor Manipulation
- Plattformübergreifend (Linux und Windows)
- Benutzerfreundliche Kommandozeilenschnittstelle
- Drag & Drop unter Windows
- Fortschrittsanzeige bei größeren Dateien
- Passwort-Stärkenprüfung

## Sicherheitsstufen

Das Programm bietet fünf verschiedene Sicherheitsstufen, die den Kompromiss zwischen Geschwindigkeit und Sicherheit kontrollieren:

1. **Stufe 1: Schnell, aber sicher**
   - AES-128-GCM
   - PBKDF2 mit 10.000 Iterationen
   - Gut für unkritische Daten

2. **Stufe 2: Ausgewogen (Standard)**
   - AES-256-GCM
   - PBKDF2 mit 100.000 Iterationen
   - Empfohlen für die meisten Anwendungsfälle

3. **Stufe 3: Erhöhte Sicherheit**
   - AES-256-GCM
   - PBKDF2 mit 250.000 Iterationen
   - Für sensiblere Daten

4. **Stufe 4: Hohe Sicherheit**
   - AES-256-GCM
   - Argon2id mit 64MB RAM-Nutzung
   - Ressourcenintensiv, sehr sicher

5. **Stufe 5: Maximale Sicherheit**
   - AES-256-GCM + ChaCha20 (doppelte Verschlüsselung)
   - Argon2id mit 256MB RAM-Nutzung
   - Extrem ressourcenintensiv, für höchstsensible Daten

## Installation

### Abhängigkeiten

- CMake 3.12 oder höher
- C++17-kompatibler Compiler (g++, MSVC)
- OpenSSL 1.1.1 oder höher
- Optional: libsodium (für optimierte ChaCha20-Implementierung)
- Optional: libargon2 (wird sonst aus den Quellen gebaut)
- Für Windows Cross-Compiling unter Linux: MinGW-w64

```bash
# Unter Ubuntu/Debian:
sudo apt install build-essential cmake libssl-dev libargon2-dev libsodium-dev
# Für Windows-Build:
sudo apt install mingw-w64
```

### Build

#### Linux-Build

```bash
mkdir build && cd build
cmake ..
make
```

#### Windows-Build unter Linux (Cross-Compiling)

```bash
mkdir build_windows && cd build_windows
cmake .. -DBUILD_WINDOWS=ON
make
```

#### Natives Windows-Build (mit Visual Studio)

```batch
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## Verwendung

### Kommandozeilenoptionen

```
encrypt [Optionen] <Datei>

Optionen:
  -h, --help              Diese Hilfe anzeigen
  -d, --decrypt           Datei entschlüsseln (Standard: verschlüsseln)
  -o, --output <Datei>    Ausgabedatei angeben
  -p, --password <Pass>   Passwort angeben (UNSICHER, besser interaktiv!)
  -l, --level <1-5>       Sicherheitsstufe angeben (1=schnell, 5=max. sicher)
  -c, --check-password    Passwort-Stärke prüfen ohne Verschlüsselung
```

### Beispiele

```bash
# Datei mit Standardsicherheit verschlüsseln (Stufe 2)
./encrypt dokument.pdf

# Datei mit hoher Sicherheit verschlüsseln (Stufe 4)
./encrypt -l 4 dokument.pdf

# Datei mit spezifischem Ausgabepfad verschlüsseln
./encrypt dokument.pdf -o geheim.dat

# Datei entschlüsseln
./encrypt -d dokument.pdf.cryp

# Passwort-Stärke prüfen
./encrypt -c

# Passwort in der Kommandozeile angeben (unsicher!)
./encrypt -p "MeinPasswort" dokument.pdf
```

### Unter Windows

Unter Windows kann die Anwendung auch per Drag & Drop verwendet werden:
1. Ziehen Sie eine Datei auf die encrypt.exe
2. Geben Sie das Passwort ein, wenn Sie dazu aufgefordert werden
3. Die Datei wird ver- oder entschlüsselt (je nach Dateierweiterung)

## Hinweise zur Sicherheit

- Verwenden Sie starke Passwörter (mindestens 12 Zeichen, Groß-/Kleinbuchstaben, Zahlen, Sonderzeichen)
- Für sensible Daten sollten Sie mindestens Sicherheitsstufe 3 wählen
- Bei hochsensiblen Daten ist Stufe 5 zu empfehlen (benötigt mehr Zeit und Ressourcen)
- Geben Sie Passwörter niemals direkt in der Kommandozeile an (kann in der Befehlshistorie gespeichert werden)
- Bewahren Sie Ihre Passwörter sicher auf - bei Verlust sind verschlüsselte Dateien nicht wiederherstellbar

## Technische Details

- Authentifizierte Verschlüsselung (AES-GCM) schützt vor Datenmanipulation
- Zufälliger Salt und IV für jede Verschlüsselung
- Argon2id ist ein moderner, speicher-harter Schlüsselableitungsalgorithmus (Memory-Hard KDF)
- ChaCha20 bietet eine zweite Verschlüsselungsschicht mit einem anderen Algorithmus

## Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert.