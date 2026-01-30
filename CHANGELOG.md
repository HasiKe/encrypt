# Changelog

Alle wichtigen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt folgt [Semantic Versioning](https://semver.org/lang/de/).

---

## [Unreleased]

### Geplant
- GUI für Linux (GTK/Qt)
- Argon2id Key Derivation als Alternative zu PBKDF2
- Hardware-Verschlüsselungs-Unterstützung (AES-NI)
- Secure Memory Wiping
- Internationalisierung (i18n)

---

## [2.0.0] - 2026-01-30

### ✨ Hinzugefügt
- **Komplette Neustrukturierung** des Projekts
- **5 Sicherheitsstufen** für verschiedene Anwendungsfälle
  - Level 1: Standard (AES-128-GCM, 10K Iterationen)
  - Level 2: Empfohlen (AES-256-GCM, 100K Iterationen)
  - Level 3: Hoch (AES-256-GCM, 250K Iterationen)
  - Level 4: Militär (AES-256-GCM, 500K Iterationen)
  - Level 5: Paranoid (Doppelte Verschlüsselung, 1M Iterationen)
- **Passwort-Stärke-Analyse** mit detaillierter Bewertung
- **Ordner-Verschlüsselung** mit Archiv-Erstellung
- **Farbige CLI-Ausgabe** mit ANSI-Codes
- **ASCII-Fortschrittsanzeige** für Dateioperationen
- **Interaktiver Passwort-Checker** Modus (`-c`)
- **CMake Build-System** mit Cross-Compilation Support
- **Umfassende Dokumentation** (DE/EN)
- **Unit-Test-Suite** für Crypto-Funktionen
- **Windows GUI** mit Drag-and-Drop Support
- **TLV-basiertes Dateiformat** für Metadaten

### 🔧 Geändert
- Projektstruktur auf modernes C++ Layout umgestellt
- Header-Dateien in `include/encrypt/` organisiert
- Plattform-spezifischer Code in eigene Module getrennt
- Verbesserte Fehlerbehandlung mit aussagekräftigen Meldungen
- Optimierte Chunk-basierte Verarbeitung (64KB Chunks)

### 🔒 Sicherheit
- AES-GCM mit authentifizierter Verschlüsselung
- PBKDF2-HMAC-SHA512 für Key Derivation
- Sichere Zufallszahlen via OpenSSL RAND_bytes
- Per-Chunk Authentifizierungs-Tags
- Geschützte Dateiheader mit Integritätsprüfung

### 📚 Dokumentation
- README.md (Deutsch)
- README_EN.md (English)
- CLAUDE.md (AI-Agent Guidelines)
- docs/DOCUMENTATION.md (Vollständige technische Dokumentation)
- CONTRIBUTING.md (Mitwirken-Richtlinien)
- CHANGELOG.md (Diese Datei)

---

## [1.0.0] - 2024-XX-XX

### Hinzugefügt
- Initiale Version
- Grundlegende AES-256 Verschlüsselung
- Einfache CLI-Oberfläche
- Windows und Linux Support

---

## Version Format

### Major (X.0.0)
Inkompatible API-Änderungen oder Dateiformat-Änderungen

### Minor (0.X.0)
Neue Features, abwärtskompatibel

### Patch (0.0.X)
Bugfixes und kleine Verbesserungen

---

## Links

- [GitHub Repository](https://github.com/HasiKe/encrypt)
- [Issue Tracker](https://github.com/HasiKe/encrypt/issues)
- [Releases](https://github.com/HasiKe/encrypt/releases)
