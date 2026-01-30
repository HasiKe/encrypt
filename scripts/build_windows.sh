#!/bin/bash
#
# Cross-Compile Skript für Encrypt (Windows .exe auf Linux)
# Verwendung: ./scripts/build_windows.sh [options]
#
# Voraussetzungen:
#   - MinGW-w64: sudo apt install mingw-w64
#
# Optionen:
#   --release     Release-Build (Standard)
#   --debug       Debug-Build
#   --clean       Build-Verzeichnis vorher löschen
#   --package     ZIP-Paket erstellen
#   --help        Diese Hilfe anzeigen

set -e

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Standardwerte
BUILD_TYPE="Release"
DO_CLEAN="OFF"
DO_PACKAGE="OFF"

# Verzeichnisse
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build-windows"
TOOLCHAIN="$PROJECT_DIR/cmake/toolchain-mingw-w64.cmake"

# Hilfsfunktion
print_help() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}     ${GREEN}Encrypt Windows Cross-Compile Script${NC}                    ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Verwendung: $0 [optionen]"
    echo ""
    echo "Optionen:"
    echo "  --release     Release-Build (Standard)"
    echo "  --debug       Debug-Build"
    echo "  --clean       Build-Verzeichnis vorher löschen"
    echo "  --package     ZIP-Paket für Windows erstellen"
    echo "  --help        Diese Hilfe anzeigen"
    echo ""
    echo "Voraussetzungen:"
    echo "  MinGW-w64 Cross-Compiler installieren:"
    echo "    sudo apt install mingw-w64"
    echo ""
    echo "Beispiele:"
    echo "  $0                      # Standard Release-Build"
    echo "  $0 --clean --package    # Sauberer Build + ZIP"
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

# Header
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}  🔐 ${BLUE}ENCRYPT${NC} - Windows Cross-Compile                          ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}     Build Script v2.0                                        ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Voraussetzungen prüfen
log_info "Prüfe Voraussetzungen..."

if ! command -v cmake &> /dev/null; then
    log_error "CMake nicht gefunden!"
    exit 1
fi
log_success "CMake: $(cmake --version | head -1)"

# MinGW prüfen
if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    log_error "MinGW-w64 nicht gefunden!"
    echo ""
    echo "Installation:"
    echo "  Ubuntu/Debian: sudo apt install mingw-w64"
    echo "  Fedora:        sudo dnf install mingw64-gcc-c++"
    echo "  Arch:          sudo pacman -S mingw-w64-gcc"
    echo ""
    exit 1
fi
log_success "MinGW-w64: $(x86_64-w64-mingw32-g++ --version | head -1)"

# Toolchain prüfen
if [ ! -f "$TOOLCHAIN" ]; then
    log_error "Toolchain-Datei nicht gefunden: $TOOLCHAIN"
    exit 1
fi
log_success "Toolchain: $TOOLCHAIN"

echo ""

# Clean
if [ "$DO_CLEAN" = "ON" ]; then
    log_info "Lösche Build-Verzeichnis..."
    rm -rf "$BUILD_DIR"
    log_success "Build-Verzeichnis gelöscht"
fi

# Build-Verzeichnis
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# CMake konfigurieren
log_info "Konfiguriere CMake für Windows..."
log_info "  Build-Typ: $BUILD_TYPE"
log_info "  Ziel: Windows x64"

cmake "$PROJECT_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DBUILD_WINDOWS=ON

log_success "CMake-Konfiguration abgeschlossen"
echo ""

# Kompilieren
log_info "Kompiliere für Windows..."
NPROC=$(nproc 2>/dev/null || echo 4)
cmake --build . --parallel "$NPROC"

log_success "Kompilierung abgeschlossen"
echo ""

# Prüfen ob EXE erstellt wurde
if [ -f "$BUILD_DIR/encrypt.exe" ]; then
    log_success "Erstellt: encrypt.exe"
    ls -lh "$BUILD_DIR/encrypt.exe"
else
    log_warn "encrypt.exe nicht gefunden, suche..."
    find "$BUILD_DIR" -name "*.exe" -type f
fi

echo ""

# Paket erstellen
if [ "$DO_PACKAGE" = "ON" ]; then
    log_info "Erstelle Windows-Paket..."
    
    PACKAGE_DIR="$BUILD_DIR/encrypt-windows"
    VERSION="2.0.0"
    
    mkdir -p "$PACKAGE_DIR"
    
    # Dateien kopieren
    cp "$BUILD_DIR/encrypt.exe" "$PACKAGE_DIR/" 2>/dev/null || true
    cp "$BUILD_DIR/encrypt_windows.exe" "$PACKAGE_DIR/encrypt.exe" 2>/dev/null || true
    cp "$PROJECT_DIR/README.md" "$PACKAGE_DIR/"
    cp "$PROJECT_DIR/README_EN.md" "$PACKAGE_DIR/"
    cp "$PROJECT_DIR/LICENSE" "$PACKAGE_DIR/"
    cp "$PROJECT_DIR/CHANGELOG.md" "$PACKAGE_DIR/"
    
    # ZIP erstellen
    cd "$BUILD_DIR"
    zip -r "encrypt-${VERSION}-windows-x64.zip" "encrypt-windows"
    
    log_success "Paket erstellt: encrypt-${VERSION}-windows-x64.zip"
    ls -lh "$BUILD_DIR/encrypt-${VERSION}-windows-x64.zip"
    echo ""
fi

# Zusammenfassung
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}  ✅ ${BLUE}WINDOWS BUILD ERFOLGREICH${NC}                                ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Binärdatei: $BUILD_DIR/encrypt.exe"
echo "  Build-Typ:  $BUILD_TYPE"
echo "  Ziel:       Windows x64"
echo ""
echo "  Test mit Wine:"
echo "    wine $BUILD_DIR/encrypt.exe --help"
echo ""
echo "  Transfer zu Windows:"
echo "    scp $BUILD_DIR/encrypt.exe user@windows-pc:~/"
echo ""
