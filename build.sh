#!/bin/bash
set -e  # Exit on error

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$BASE_DIR/build"
BUILD_WIN_DIR="$BASE_DIR/build_windows"

# Sicherstellen, dass die Build-Verzeichnisse existieren
mkdir -p "$BUILD_DIR"
mkdir -p "$BUILD_WIN_DIR"

echo "################################################"
echo "### Kompiliere Linux-Version ###"
echo "################################################"
cd "$BUILD_DIR"
rm -rf *
cmake ..
make -j4

echo "################################################"
echo "### Kompiliere Windows-Version ###"
echo "################################################"
cd "$BUILD_WIN_DIR"
rm -rf *

# Windows-Build mit Toolchain-Datei
cmake -DCMAKE_TOOLCHAIN_FILE="$BASE_DIR/cmake/toolchain-mingw-w64.cmake" ..
make -j4

echo "################################################"
echo "### Build abgeschlossen ###"
echo "################################################"
echo "Linux-Executable: $BUILD_DIR/bin/encrypt"
if [ -f "$BUILD_WIN_DIR/bin/encrypt.exe" ]; then
    echo "Windows-Executable: $BUILD_WIN_DIR/bin/encrypt.exe"
    echo "BUILD ERFOLGREICH!"
else
    echo "Windows-Build fehlgeschlagen!"
    echo "BUILD FEHLGESCHLAGEN!"
    exit 1
fi