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
    OUTPUT_NAME "encrypt_decrypt"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/Linux"
)

# Windows-Build konfigurieren (unter Verwendung der Cross-Toolchain-Datei)
if (WIN32)
    add_executable(encrypt_decrypt_windows WIN32 ${SRC_FILES} ${CMAKE_SOURCE_DIR}/resources/resources.rc)
    set_target_properties(encrypt_decrypt_windows PROPERTIES
        OUTPUT_NAME "encrypt_decrypt"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/Windows"
    )
endif()



if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -static-libgcc -static-libstdc++")
endif()


# Toolchain nur für das Windows-Target anwenden
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_SOURCE_DIR}/cmake/toolchain-mingw-w64.cmake")
target_compile_options(encrypt_decrypt_windows PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-mwindows>)

# Header-Dateien einbinden
target_include_directories(encrypt_decrypt_linux PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_include_directories(encrypt_decrypt_windows PRIVATE "${CMAKE_SOURCE_DIR}/src")
