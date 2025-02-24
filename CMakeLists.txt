# Mindestanforderung an die CMake-Version
cmake_minimum_required(VERSION 3.10)

# Projektname und Sprache
project(EncryptionProject LANGUAGES CXX)

# Setzen des Standard-C++-Standards
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Einbinden aller Quelldateien
file(GLOB SRC_FILES "${CMAKE_SOURCE_DIR}/src/*.cpp")

# Linux-Build konfigurieren
add_executable(encrypt_decrypt_linux ${SRC_FILES})
set_target_properties(encrypt_decrypt_linux PROPERTIES
    OUTPUT_NAME "encrypt"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/Linux"
)
target_include_directories(encrypt_decrypt_linux PRIVATE "${CMAKE_SOURCE_DIR}/include")

# Windows-Build konfigurieren
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_SOURCE_DIR}/cmake/toolchain-mingw-w64.cmake" CACHE STRING "Toolchain file for cross-compiling to Windows" FORCE)
add_executable(encrypt_decrypt_windows WIN32 ${SRC_FILES} ${CMAKE_SOURCE_DIR}/resources/resources.rc)
set_target_properties(encrypt_decrypt_windows PROPERTIES
    OUTPUT_NAME "encrypt.exe"  # Setzt die Ausgabe explizit auf .exe
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/Windows"
)
target_include_directories(encrypt_decrypt_windows PRIVATE "${CMAKE_SOURCE_DIR}/src")

# Statische Kompilierung sicherstellen
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND "${CMAKE_CXX_COMPILER}" MATCHES ".*mingw.*")
    # Statische Verlinkung aller Standardbibliotheken und Ressourcen
    target_compile_options(encrypt_decrypt_windows PRIVATE -static -static-libgcc -static-libstdc++ -mwindows)
    target_link_options(encrypt_decrypt_windows PRIVATE -static -static-libgcc -static-libstdc++)
endif()
