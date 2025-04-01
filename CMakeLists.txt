cmake_minimum_required(VERSION 3.12)

# Projektname und Sprache
project(EncryptionTool 
    VERSION 1.0.0
    DESCRIPTION "Sicheres Dateiverschlüsselungstool"
    LANGUAGES CXX
)

# C++ Standard setzen
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler-Warnungen aktivieren
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Ausgabeverzeichnisse festlegen
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Prüfe, ob wir explizit für Windows kompilieren
option(BUILD_WINDOWS "Cross-compile für Windows" OFF)

# Kryptographie-Bibliotheken finden
if(BUILD_WINDOWS)
    # Für Windows-Cross-Compiling: verwende eigene einfache Krypto-Implementierung
    message(STATUS "Cross-compiling für Windows: Verwende Simple-Crypto statt OpenSSL")
    set(OPENSSL_INCLUDE_DIR "")
    set(OPENSSL_LIBRARIES "")
    add_definitions(-DUSE_SIMPLE_CRYPTO)
else()
    # Normale OpenSSL-Suche für Linux
    # Setze Option für statische Bibliotheken, wenn für Windows gebaut wird
    if(WIN32)
        set(OPENSSL_USE_STATIC_LIBS TRUE)
    endif()
    find_package(OpenSSL REQUIRED)
    message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
endif()

# Header-Verzeichnisse
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# Abhängig von den vorhandenen Bibliotheken auf dem System
option(USE_SYSTEM_LIBSODIUM "Verwende System libsodium wenn verfügbar" ON)

# Wenn Windows-Build, simuliere auch libsodium
if(BUILD_WINDOWS)
    message(STATUS "Cross-compiling für Windows: libsodium wird simuliert")
    set(USE_LIBSODIUM OFF)
    add_definitions(-DSIMULATED_SODIUM)
else()
    # Prüfen auf libsodium für ChaCha20
    find_library(SODIUM_LIBRARY sodium)
    if(USE_SYSTEM_LIBSODIUM AND SODIUM_LIBRARY)
        message(STATUS "Verwende System libsodium: ${SODIUM_LIBRARY}")
        set(USE_LIBSODIUM ON)
        find_path(SODIUM_INCLUDE_DIR sodium.h)
        include_directories(${SODIUM_INCLUDE_DIR})
    else()
        message(STATUS "Libsodium nicht gefunden, verwende OpenSSL für ChaCha20")
        set(USE_LIBSODIUM OFF)
    endif()
endif()

# Da Argon2 für Tests nicht vorhanden ist, simulieren wir dessen Verfügbarkeit
# In einer echten Anwendung sollte es ordnungsgemäß installiert werden
add_definitions(-DSIMULATED_ARGON2)
include_directories(${CMAKE_SOURCE_DIR}/lib/argon2/include)

# Kompilierungsflags setzen
add_definitions(-DOPENSSL_API_COMPAT=0x10100000L)

if(USE_LIBSODIUM)
    add_definitions(-DUSE_LIBSODIUM)
endif()

# Quellverzeichnisse 
set(CORE_SOURCES
    src/core/crypto.cpp
)

set(PLATFORM_SOURCES_LINUX
    src/platform/linux.cpp
)

set(PLATFORM_SOURCES_WINDOWS
    src/platform/windows.cpp
)

# Windows-Resourcen
if(BUILD_WINDOWS)
    # Für Cross-Compile müssen wir sicherstellen, dass die RC-Dateien korrekt verarbeitet werden
    if(EXISTS "${CMAKE_SOURCE_DIR}/resources/resources.rc")
        message(STATUS "Adding resource file for Windows build")
        list(APPEND PLATFORM_SOURCES_WINDOWS "${CMAKE_SOURCE_DIR}/resources/resources.rc")
    else()
        message(STATUS "Resource file not found, Windows build might have limited functionality")
    endif()
else()
    # Resourcendatei für native Windows-Builds
    if(EXISTS "${CMAKE_SOURCE_DIR}/resources/resources.rc" AND WIN32)
        list(APPEND PLATFORM_SOURCES_WINDOWS "${CMAKE_SOURCE_DIR}/resources/resources.rc")
    endif()
endif()

set(UI_SOURCES
    src/ui/cli.cpp
)

# Thread-Bibliothek finden
find_package(Threads REQUIRED)

# Gemeinsame Bibliothek erstellen
add_library(encrypt_core STATIC ${CORE_SOURCES})
target_include_directories(encrypt_core PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(encrypt_core 
    PUBLIC 
    ${OPENSSL_LIBRARIES}
    $<$<BOOL:${USE_LIBSODIUM}>:${SODIUM_LIBRARY}>
    Threads::Threads
)

# Linux-Build erstellen
if(UNIX AND NOT APPLE)
    add_executable(encrypt_linux 
        src/main.cpp
        ${UI_SOURCES}
        ${PLATFORM_SOURCES_LINUX}
    )
    
    target_link_libraries(encrypt_linux PRIVATE encrypt_core)
    
    # Ausgabename festlegen
    set_target_properties(encrypt_linux PROPERTIES
        OUTPUT_NAME "encrypt"
    )
endif()

# Windows Cross-Compile-Build konfigurieren
if(BUILD_WINDOWS AND CMAKE_CROSSCOMPILING)
    # Prüfe, ob MinGW-Compiler existieren
    find_program(MINGW_CXX_COMPILER x86_64-w64-mingw32-g++)
    find_program(MINGW_C_COMPILER x86_64-w64-mingw32-gcc)
    find_program(MINGW_RC_COMPILER x86_64-w64-mingw32-windres)
    
    if(NOT MINGW_CXX_COMPILER OR NOT MINGW_C_COMPILER)
        message(FATAL_ERROR "MinGW-Compiler nicht gefunden. Bitte installieren Sie mingw-w64.")
    endif()
    
    # Windows-Binary erstellen
    add_executable(encrypt_windows 
        src/main.cpp
        ${UI_SOURCES}
        ${PLATFORM_SOURCES_WINDOWS}
    )
    
    # Windows-spezifische Compiler-Flags
    target_compile_options(encrypt_windows PRIVATE "-mwindows")
    
    # Statische Verlinkung für Windows - alle Bibliotheken statisch einbinden
    target_link_libraries(encrypt_windows PRIVATE 
        encrypt_core
    )
    
    # Statische Verlinkung aller Bibliotheken für komplett eigenständige Anwendung
    set_target_properties(encrypt_windows PROPERTIES
        OUTPUT_NAME "encrypt"
        SUFFIX ".exe"
        LINK_FLAGS "-static -static-libgcc -static-libstdc++ -Wl,-Bstatic"
    )
    
    # Zusätzliche Info-Meldung
    message(STATUS "Windows-Build mit statisch eingebundenen Bibliotheken konfiguriert")
endif()

# Natives Windows-Build konfigurieren (auf Windows-System)
if(WIN32)
    add_executable(encrypt_native WIN32
        src/main.cpp
        ${UI_SOURCES}
        ${PLATFORM_SOURCES_WINDOWS}
    )
    
    # Statische Verlinkung für Windows - alle Bibliotheken statisch einbinden
    target_link_libraries(encrypt_native PRIVATE encrypt_core)
    
    # Statische Verlinkung aller Bibliotheken für komplett eigenständige Anwendung
    set_target_properties(encrypt_native PROPERTIES
        OUTPUT_NAME "encrypt"
        LINK_FLAGS "-static -static-libgcc -static-libstdc++ -Wl,-Bstatic"
    )
    
    message(STATUS "Windows-Native-Build mit statisch eingebundenen Bibliotheken konfiguriert")
endif()

# Standard-Installationsverzeichnis setzen
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    if(WIN32)
        set(CMAKE_INSTALL_PREFIX "C:/Program Files/Encrypt" CACHE PATH "..." FORCE)
    else()
        set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "..." FORCE)
    endif()
endif()

# Installationsverzeichnis für Windows-Builds anpassen
if(BUILD_WINDOWS)
    set(INSTALL_DEST "${CMAKE_BINARY_DIR}/install")
    
    # Erstelle install-Verzeichnis wenn nötig
    file(MAKE_DIRECTORY ${INSTALL_DEST})
    
    # Kopiere Windows-Exe direkt nach dem Build
    add_custom_command(
        TARGET encrypt_windows POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_FILE:encrypt_windows>
                ${INSTALL_DEST}/encrypt.exe
        COMMENT "Kopiere encrypt.exe nach ${INSTALL_DEST}"
    )
    
    # Kopiere Installationsskript
    add_custom_command(
        TARGET encrypt_windows POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_SOURCE_DIR}/install_windows.bat
                ${INSTALL_DEST}/install.bat
        COMMENT "Kopiere Installationsskript nach ${INSTALL_DEST}"
    )
    
    # Erstelle README für Windows-Installation
    file(WRITE ${CMAKE_BINARY_DIR}/install/README.txt 
        "Encrypt - Datei-Verschlüsselungsprogramm\n"
        "======================================\n\n"
        "Installation:\n"
        "1. Führen Sie install.bat aus, um das Programm zu installieren\n"
        "   Dies installiert das Programm in Ihrem Benutzerverzeichnis und\n"
        "   erstellt eine Desktop-Verknüpfung.\n\n"
        "Manuelle Installation:\n"
        "Falls Sie keine automatische Installation wünschen, können Sie\n"
        "encrypt.exe an einen beliebigen Ort kopieren und direkt ausführen.\n\n"
        "Verwendung:\n"
        "- Doppelklick auf encrypt.exe, um das Programm zu starten\n"
        "- Ziehen Sie Dateien per Drag & Drop in das Programmfenster\n"
        "- Oder: Drag & Drop direkt auf die encrypt.exe\n\n"
        "Support: https://github.com/HasiKe/encrypt\n"
    )
    
    # Ausgabe mit Installationsinformation
    add_custom_command(
        TARGET encrypt_windows POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo
                "Windows-Build fertig. Installationspaket ist im Verzeichnis ${INSTALL_DEST}"
    )
endif()

# Installationsziele
install(TARGETS encrypt_core
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

if(UNIX AND NOT APPLE)
    install(TARGETS encrypt_linux
        RUNTIME DESTINATION bin
    )
endif()

if(WIN32)
    install(TARGETS encrypt_native
        RUNTIME DESTINATION bin
    )
endif()

if(UNIX AND NOT APPLE AND BUILD_WINDOWS AND CMAKE_CROSSCOMPILING)
    install(TARGETS encrypt_windows
        RUNTIME DESTINATION bin
    )
    
    # Zusätzliches explizites Installationsziel für Windows-Build
    install(FILES ${CMAKE_BINARY_DIR}/bin/encrypt.exe
            DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
            PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                        GROUP_READ GROUP_EXECUTE
                        WORLD_READ WORLD_EXECUTE)
endif()

# Tests
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()