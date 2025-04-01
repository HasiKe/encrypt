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

# Kryptographie-Bibliotheken finden
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

# Header-Verzeichnisse
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# Abhängig von den vorhandenen Bibliotheken auf dem System
option(USE_SYSTEM_LIBSODIUM "Verwende System libsodium wenn verfügbar" ON)

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
    resources/resources.rc
)

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

# Windows Cross-Compile-Build konfigurieren (unter Linux)
if(UNIX AND NOT APPLE)
    option(BUILD_WINDOWS "Cross-compile für Windows" OFF)
    
    if(BUILD_WINDOWS)
        # Setze Toolchain-Datei
        include(${CMAKE_SOURCE_DIR}/cmake/toolchain-mingw-w64.cmake)
        
        # Windows-Binary erstellen
        add_executable(encrypt_windows 
            src/main.cpp
            ${UI_SOURCES}
            ${PLATFORM_SOURCES_WINDOWS}
        )
        
        # Windows-spezifische Compiler-Flags
        target_compile_options(encrypt_windows PRIVATE -mwindows)
        
        # Statische Verlinkung für Windows
        target_link_libraries(encrypt_windows PRIVATE 
            encrypt_core
            -static -static-libgcc -static-libstdc++
        )
        
        # Ausgabename festlegen
        set_target_properties(encrypt_windows PROPERTIES
            OUTPUT_NAME "encrypt"
            SUFFIX ".exe"
        )
    endif()
endif()

# Natives Windows-Build konfigurieren (auf Windows-System)
if(WIN32)
    add_executable(encrypt_native WIN32
        src/main.cpp
        ${UI_SOURCES}
        ${PLATFORM_SOURCES_WINDOWS}
    )
    
    target_link_libraries(encrypt_native PRIVATE encrypt_core)
    
    # Ausgabename festlegen
    set_target_properties(encrypt_native PROPERTIES
        OUTPUT_NAME "encrypt"
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

if(UNIX AND NOT APPLE AND BUILD_WINDOWS)
    install(TARGETS encrypt_windows
        RUNTIME DESTINATION bin
    )
endif()

# Tests
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()