# =============================================================================
# Encrypt Examples - CMake Build Configuration
# =============================================================================

cmake_minimum_required(VERSION 3.12)

# Beispiele nur bauen wenn als Teil des Hauptprojekts
if(NOT TARGET encrypt_core)
    message(FATAL_ERROR "Examples must be built as part of the main project")
endif()

# -----------------------------------------------------------------------------
# Basic Usage Example
# -----------------------------------------------------------------------------
add_executable(example_basic_usage basic_usage.cpp)
target_link_libraries(example_basic_usage PRIVATE encrypt_core)
target_include_directories(example_basic_usage PRIVATE ${PROJECT_SOURCE_DIR}/include)

# -----------------------------------------------------------------------------
# Folder Encryption Example
# -----------------------------------------------------------------------------
add_executable(example_folder_encryption folder_encryption.cpp)
target_link_libraries(example_folder_encryption PRIVATE encrypt_core)
target_include_directories(example_folder_encryption PRIVATE ${PROJECT_SOURCE_DIR}/include)

# -----------------------------------------------------------------------------
# Installation (optional)
# -----------------------------------------------------------------------------
install(TARGETS example_basic_usage example_folder_encryption
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/examples
    OPTIONAL
)

# Quellcode der Beispiele auch installieren
install(FILES
    basic_usage.cpp
    folder_encryption.cpp
    DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples
    OPTIONAL
)

message(STATUS "Examples configured: basic_usage, folder_encryption")
