#!/bin/bash

# Build-Skript für Windows-Version von Encrypt

# Farben für Ausgabe
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Prüfe, ob mingw-w64 installiert ist
if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo -e "${RED}Fehler: x86_64-w64-mingw32-g++ nicht gefunden.${NC}"
    echo "Bitte installieren Sie mingw-w64:"
    echo "  sudo apt install mingw-w64"
    exit 1
fi

# Erstelle Build-Verzeichnis
BUILD_DIR="build_windows"
echo -e "${BLUE}Erstelle Build-Verzeichnis: ${BUILD_DIR}${NC}"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR" || exit 1

# Konfiguriere Build mit CMake
echo -e "${BLUE}Konfiguriere Windows-Build...${NC}"
if cmake -DBUILD_WINDOWS=ON -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-mingw-w64.cmake ..; then
    echo -e "${GREEN}Konfiguration erfolgreich.${NC}"
else
    echo -e "${RED}Fehler bei der Konfiguration!${NC}"
    exit 1
fi

# Kompiliere Projekt
echo -e "${BLUE}Kompiliere Windows-Version...${NC}"
if make -j$(nproc); then
    echo -e "${GREEN}Kompilierung erfolgreich.${NC}"
else
    echo -e "${RED}Fehler bei der Kompilierung!${NC}"
    exit 1
fi

# Zeige Pfad zum Installationspaket an
INSTALL_DIR="$(pwd)/install"
echo -e "${GREEN}Build abgeschlossen!${NC}"
echo -e "Windows-Installationspaket befindet sich in:"
echo -e "${BLUE}$INSTALL_DIR${NC}"

# Erstelle Zip-Datei für einfache Distribution
echo -e "${BLUE}Erstelle ZIP-Archiv...${NC}"
cd install || exit 1
ZIP_FILE="../encrypt-windows.zip"
zip -r "$ZIP_FILE" ./*

if [ $? -eq 0 ]; then
    echo -e "${GREEN}ZIP-Archiv erfolgreich erstellt: $(cd .. && pwd)/encrypt-windows.zip${NC}"
else
    echo -e "${RED}Fehler beim Erstellen des ZIP-Archivs!${NC}"
fi

echo -e "${GREEN}Fertig!${NC}"