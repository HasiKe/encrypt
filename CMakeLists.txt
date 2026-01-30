#===============================================================================
# Encrypt - Military-grade File Encryption
# CMake Build Configuration
#===============================================================================

cmake_minimum_required(VERSION 3.12)

project(encrypt
    VERSION 2.0.0
    DESCRIPTION "Military-grade file encryption tool"
    LANGUAGES CXX
)

#-------------------------------------------------------------------------------
# Build Options
#-------------------------------------------------------------------------------

option(BUILD_WINDOWS "Build Windows version (requires MinGW-w64)" OFF)
option(BUILD_TESTS "Build test suite" OFF)
option(BUILD_EXAMPLES "Build example programs" OFF)
option(USE_SYSTEM_LIBSODIUM "Use system libsodium instead of bundled" OFF)

#-------------------------------------------------------------------------------
# Compiler Settings
#-------------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Warning flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror=return-type)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O3)
    else()
        add_compile_options(-g -O0)
    endif()
elseif(MSVC)
    add_compile_options(/W4 /WX)
endif()

#-------------------------------------------------------------------------------
# Platform Detection
#-------------------------------------------------------------------------------

if(BUILD_WINDOWS)
    message(STATUS "Building for Windows (cross-compilation)")
    set(PLATFORM_WINDOWS TRUE)
else()
    if(WIN32)
        set(PLATFORM_WINDOWS TRUE)
    elseif(APPLE)
        set(PLATFORM_MACOS TRUE)
    else()
        set(PLATFORM_LINUX TRUE)
    endif()
endif()

#-------------------------------------------------------------------------------
# Dependencies
#-------------------------------------------------------------------------------

# OpenSSL (required for Linux/macOS)
if(NOT PLATFORM_WINDOWS OR NOT BUILD_WINDOWS)
    find_package(OpenSSL REQUIRED)
    message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
endif()

# libsodium (optional, for ChaCha20)
if(USE_SYSTEM_LIBSODIUM)
    find_package(PkgConfig)
    if(PkgConfig_FOUND)
        pkg_check_modules(SODIUM libsodium)
    endif()
endif()

#-------------------------------------------------------------------------------
# Source Files
#-------------------------------------------------------------------------------

set(CORE_SOURCES
    src/core/crypto.cpp
)

# Platform-specific utility sources for core library
if(BUILD_WINDOWS)
    set(PLATFORM_CORE_SOURCES src/platform/windows.cpp)
else()
    set(PLATFORM_CORE_SOURCES src/platform/linux.cpp)
endif()

set(LINUX_SOURCES
    src/main.cpp
    src/ui/cli.cpp
)

set(WINDOWS_SOURCES
    src/main.cpp
    src/ui/cli.cpp
)

set(HEADERS
    include/encrypt/crypto.h
    include/encrypt/platform.h
)

#-------------------------------------------------------------------------------
# Core Library
#-------------------------------------------------------------------------------

add_library(encrypt_core STATIC ${CORE_SOURCES} ${PLATFORM_CORE_SOURCES} ${HEADERS})

target_include_directories(encrypt_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(NOT PLATFORM_WINDOWS OR NOT BUILD_WINDOWS)
    target_link_libraries(encrypt_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

if(SODIUM_FOUND)
    target_link_libraries(encrypt_core PUBLIC ${SODIUM_LIBRARIES})
    target_include_directories(encrypt_core PUBLIC ${SODIUM_INCLUDE_DIRS})
    target_compile_definitions(encrypt_core PUBLIC HAVE_LIBSODIUM=1)
endif()

#-------------------------------------------------------------------------------
# Linux/macOS Executable
#-------------------------------------------------------------------------------

if(NOT BUILD_WINDOWS)
    add_executable(encrypt ${LINUX_SOURCES})
    target_link_libraries(encrypt PRIVATE encrypt_core)
    
    # Install rules
    install(TARGETS encrypt
        RUNTIME DESTINATION bin
    )
    
    install(FILES ${HEADERS}
        DESTINATION include/encrypt
    )
endif()

#-------------------------------------------------------------------------------
# Windows Cross-Compilation
#-------------------------------------------------------------------------------

if(BUILD_WINDOWS)
    # Use MinGW-w64 toolchain
    if(NOT CMAKE_TOOLCHAIN_FILE)
        message(WARNING "No toolchain file specified. Use -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw-w64.cmake")
    endif()
    
    add_executable(encrypt_windows WIN32 ${WINDOWS_SOURCES})
    target_link_libraries(encrypt_windows PRIVATE encrypt_core)
    
    # Windows libraries
    target_link_libraries(encrypt_windows PRIVATE
        comctl32
        shlwapi
        shell32
    )
    
    # Set output name
    set_target_properties(encrypt_windows PROPERTIES
        OUTPUT_NAME "encrypt"
        SUFFIX ".exe"
    )
    
    # Resource file (if exists)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/resources/resources.rc")
        target_sources(encrypt_windows PRIVATE resources/resources.rc)
    endif()
    
    # Install
    install(TARGETS encrypt_windows
        RUNTIME DESTINATION .
    )
endif()

#-------------------------------------------------------------------------------
# Tests
#-------------------------------------------------------------------------------

if(BUILD_TESTS)
    enable_testing()
    
    add_executable(encrypt_test test/crypto_test.cpp)
    target_link_libraries(encrypt_test PRIVATE encrypt_core)
    
    add_test(NAME CryptoTest COMMAND encrypt_test)
endif()

#-------------------------------------------------------------------------------
# Examples
#-------------------------------------------------------------------------------

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

#-------------------------------------------------------------------------------
# CPack Configuration
#-------------------------------------------------------------------------------

set(CPACK_PACKAGE_NAME "encrypt")
set(CPACK_PACKAGE_VENDOR "HasiKe")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Military-grade file encryption tool")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

if(PLATFORM_LINUX)
    set(CPACK_GENERATOR "TGZ;DEB;RPM")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl1.1 | libssl3")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "HasiKe")
elseif(PLATFORM_WINDOWS)
    set(CPACK_GENERATOR "ZIP;NSIS")
    set(CPACK_NSIS_DISPLAY_NAME "Encrypt")
    set(CPACK_NSIS_PACKAGE_NAME "Encrypt")
endif()

include(CPack)

#-------------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------------

message(STATUS "")
message(STATUS "=== Encrypt Build Configuration ===")
message(STATUS "Version:        ${PROJECT_VERSION}")
message(STATUS "Build Type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "Platform:       ${CMAKE_SYSTEM_NAME}")
message(STATUS "Compiler:       ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "C++ Standard:   ${CMAKE_CXX_STANDARD}")
if(NOT BUILD_WINDOWS)
    message(STATUS "OpenSSL:        ${OPENSSL_VERSION}")
endif()
if(SODIUM_FOUND)
    message(STATUS "libsodium:      Found")
else()
    message(STATUS "libsodium:      Not found (ChaCha20 via OpenSSL)")
endif()
message(STATUS "Build Tests:    ${BUILD_TESTS}")
message(STATUS "Build Examples: ${BUILD_EXAMPLES}")
message(STATUS "Build Windows:  ${BUILD_WINDOWS}")
message(STATUS "")
