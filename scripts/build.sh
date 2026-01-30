#!/bin/bash
#
# Build-Skript für Encrypt (Linux)
# Verwendung: ./scripts/build.sh [options]
#
# Optionen:
#   --release     Release-Build (Standard)
#   --debug       Debug-Build
#   --tests       Tests aktivieren
#   --install     Nach dem Build installieren
#   --clean       Build-Verzeichnis vorher löschen
#   --package     Pakete erstellen (DEB, RPM, TGZ)
#   --help        Diese Hilfe anzeigen

set -e

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Standardwerte
BUILD_TYPE="Release"
BUILD_TESTS="OFF"
DO_INSTALL="OFF"
DO_CLEAN="OFF"
DO_PACKAGE="OFF"

# Skript-Verzeichnis ermitteln
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"

# Hilfsfunktion
print_help() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}     ${GREEN}Encrypt Build Script${NC}                                     ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Verwendung: $0 [optionen]"
    echo ""
    echo "Optionen:"
    echo "  --release     Release-Build (Standard, optimiert)"
    echo "  --debug       Debug-Build (mit Debug-Symbolen)"
    echo "  --tests       Tests kompilieren und aktivieren"
    echo "  --install     Nach dem Build systemweit installieren"
    echo "  --clean       Build-Verzeichnis vorher löschen"
    echo "  --package     Pakete erstellen (DEB, RPM, TGZ)"
    echo "  --help        Diese Hilfe anzeigen"
    echo ""
    echo "Beispiele:"
    echo "  $0                      # Standard Release-Build"
    echo "  $0 --debug --tests      # Debug-Build mit Tests"
    echo "  $0 --clean --package    # Sauberer Build + Pakete"
    echo ""
}

# Log-Funktionen
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Argumente parsen
while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            BUILD_TYPE="Release"
            shift
            ;;
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --tests)
            BUILD_TESTS="ON"
            shift
            ;;
        --install)
            DO_INSTALL="ON"
            shift
            ;;
        --clean)
            DO_CLEAN="ON"
            shift
            ;;
        --package)
            DO_PACKAGE="ON"
            shift
            ;;
        --help|-h)
            print_help
            exit 0
            ;;
        *)
            log_error "Unbekannte Option: $1"
            print_help
            exit 1
            ;;
    esac
done

# Header anzeigen
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}  🔐 ${BLUE}ENCRYPT${NC} - Military-Grade File Encryption                 ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}     Build Script v2.0                                        ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Voraussetzungen prüfen
log_info "Prüfe Voraussetzungen..."

if ! command -v cmake &> /dev/null; then
    log_error "CMake nicht gefunden! Bitte installieren: sudo apt install cmake"
    exit 1
fi
log_success "CMake gefunden: $(cmake --version | head -1)"

if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
    log_error "C++ Compiler nicht gefunden! Bitte installieren: sudo apt install g++"
    exit 1
fi

if command -v g++ &> /dev/null; then
    log_success "GCC gefunden: $(g++ --version | head -1)"
fi

# OpenSSL prüfen
if ! pkg-config --exists openssl 2>/dev/null; then
    log_warn "OpenSSL Development-Pakete nicht gefunden"
    log_info "Installation: sudo apt install libssl-dev"
fi

echo ""

# Clean wenn gewünscht
if [ "$DO_CLEAN" = "ON" ]; then
    log_info "Lösche Build-Verzeichnis..."
    rm -rf "$BUILD_DIR"
    log_success "Build-Verzeichnis gelöscht"
fi

# Build-Verzeichnis erstellen
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# CMake konfigurieren
log_info "Konfiguriere CMake..."
log_info "  Build-Typ: $BUILD_TYPE"
log_info "  Tests: $BUILD_TESTS"

cmake "$PROJECT_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DBUILD_TESTS="$BUILD_TESTS"

log_success "CMake-Konfiguration abgeschlossen"
echo ""

# Kompilieren
log_info "Kompiliere Projekt..."
NPROC=$(nproc 2>/dev/null || echo 4)
cmake --build . --parallel "$NPROC"

log_success "Kompilierung abgeschlossen"
echo ""

# Tests ausführen wenn aktiviert
if [ "$BUILD_TESTS" = "ON" ]; then
    log_info "Führe Tests aus..."
    ctest --verbose --output-on-failure
    log_success "Alle Tests bestanden"
    echo ""
fi

# Installieren wenn gewünscht
if [ "$DO_INSTALL" = "ON" ]; then
    log_info "Installiere..."
    sudo cmake --install .
    log_success "Installation abgeschlossen"
    echo ""
fi

# Pakete erstellen wenn gewünscht
if [ "$DO_PACKAGE" = "ON" ]; then
    log_info "Erstelle Pakete..."
    cpack -G "TGZ;DEB"
    
    if command -v rpmbuild &> /dev/null; then
        cpack -G "RPM"
    else
        log_warn "rpmbuild nicht gefunden, RPM-Paket übersprungen"
    fi
    
    log_success "Pakete erstellt in: $BUILD_DIR"
    ls -la *.tar.gz *.deb *.rpm 2>/dev/null || true
    echo ""
fi

# Zusammenfassung
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}  ✅ ${BLUE}BUILD ERFOLGREICH${NC}                                        ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Binärdatei: $BUILD_DIR/encrypt"
echo "  Build-Typ:  $BUILD_TYPE"
echo ""
echo "  Verwendung:"
echo "    $BUILD_DIR/encrypt <datei>           # Datei verschlüsseln"
echo "    $BUILD_DIR/encrypt <datei.enc>       # Datei entschlüsseln"
echo "    $BUILD_DIR/encrypt -h                # Hilfe anzeigen"
echo ""
