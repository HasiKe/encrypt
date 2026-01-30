/**
 * @file platform.h
 * @brief Platform-specific abstraction layer
 * @author HasiKe
 * @version 2.0.0
 * @date 2026
 * 
 * @copyright MIT License
 * 
 * Provides platform-independent interface for user interaction,
 * file system operations, and system utilities.
 */

#ifndef ENCRYPT_PLATFORM_H
#define ENCRYPT_PLATFORM_H

#include "crypto.h"
#include <string>
#include <vector>

namespace encrypt {
namespace platform {

//=============================================================================
// User Interaction
//=============================================================================

/**
 * @brief Display a message to the user
 * @param message Message text
 * @param title Optional dialog title (GUI) or prefix (CLI)
 * @param isError true for error styling
 */
void showMessage(const std::string& message, 
                 const std::string& title = "",
                 bool isError = false);

/**
 * @brief Get password from user (hidden input)
 * @param prompt Prompt text
 * @param confirm Request password confirmation
 * @return Entered password or empty string if cancelled
 */
std::string getPassword(const std::string& prompt = "Enter password: ",
                        bool confirm = false);

/**
 * @brief Get security level selection from user
 * @return Selected security level
 */
SecurityLevel getSecurityLevel();

/**
 * @brief Ask user a yes/no question
 * @param question Question text
 * @param defaultYes Default answer is yes
 * @return true if user answers yes
 */
bool askConfirmation(const std::string& question, bool defaultYes = true);

/**
 * @brief Show progress to user
 * @param current Current progress value
 * @param total Total value
 * @param message Optional status message
 */
void showProgress(uint64_t current, uint64_t total, 
                  const std::string& message = "");

/**
 * @brief Clear progress display
 */
void clearProgress();

//=============================================================================
// File System Operations
//=============================================================================

/**
 * @brief Normalize file path for current platform
 * @param path Input path
 * @return Normalized path
 */
std::string normalizePath(const std::string& path);

/**
 * @brief Check if file exists
 * @param path File path
 * @return true if file exists
 */
bool fileExists(const std::string& path);

/**
 * @brief Check if path is a directory
 * @param path Path to check
 * @return true if path is a directory
 */
bool isDirectory(const std::string& path);

/**
 * @brief Get file size
 * @param path File path
 * @return File size in bytes, or 0 if file doesn't exist
 */
uint64_t getFileSize(const std::string& path);

/**
 * @brief Get filename from path
 * @param path Full path
 * @return Filename without directory
 */
std::string getFilename(const std::string& path);

/**
 * @brief Get directory from path
 * @param path Full path
 * @return Directory without filename
 */
std::string getDirectory(const std::string& path);

/**
 * @brief Get file extension
 * @param path File path
 * @return Extension including dot (e.g., ".txt")
 */
std::string getExtension(const std::string& path);

/**
 * @brief Remove file extension
 * @param path File path
 * @return Path without extension
 */
std::string removeExtension(const std::string& path);

/**
 * @brief Create directory (and parents if needed)
 * @param path Directory path
 * @return true if created or already exists
 */
bool createDirectory(const std::string& path);

/**
 * @brief List files in directory
 * @param path Directory path
 * @param recursive Include subdirectories
 * @return List of file paths
 */
std::vector<std::string> listFiles(const std::string& path, 
                                   bool recursive = false);

/**
 * @brief Delete file
 * @param path File path
 * @return true if deleted
 */
bool deleteFile(const std::string& path);

/**
 * @brief Get temporary directory
 * @return Path to temp directory
 */
std::string getTempDirectory();

/**
 * @brief Generate unique temporary filename
 * @param prefix Filename prefix
 * @return Unique temp file path
 */
std::string getTempFilename(const std::string& prefix = "encrypt_");

//=============================================================================
// High-Level Operations
//=============================================================================

/**
 * @brief Process file (auto-detect encrypt/decrypt)
 * @param inputPath Input file path
 * @param password Password (prompt if empty)
 * @param level Security level (prompt if encrypting and LEVEL_1)
 * @return EncryptionResult with operation status
 * 
 * Automatically detects whether to encrypt or decrypt based on
 * file extension and header.
 */
EncryptionResult processFile(
    const std::string& inputPath,
    const std::string& password = "",
    SecurityLevel level = SecurityLevel::LEVEL_1
);

/**
 * @brief Process multiple files
 * @param paths List of input paths
 * @param password Password (prompt if empty)
 * @param level Security level
 * @return Vector of results for each file
 */
std::vector<EncryptionResult> processFiles(
    const std::vector<std::string>& paths,
    const std::string& password = "",
    SecurityLevel level = SecurityLevel::LEVEL_2
);

//=============================================================================
// System Utilities
//=============================================================================

/**
 * @brief Get platform name
 * @return "Windows", "Linux", "macOS", etc.
 */
std::string getPlatformName();

/**
 * @brief Check if running in GUI mode
 * @return true if GUI is available
 */
bool isGuiAvailable();

/**
 * @brief Get current working directory
 * @return Current directory path
 */
std::string getCurrentDirectory();

/**
 * @brief Set terminal/console title
 * @param title Title text
 */
void setConsoleTitle(const std::string& title);

/**
 * @brief Clear terminal/console screen
 */
void clearScreen();

/**
 * @brief Enable/disable colored output
 * @param enable true to enable colors
 */
void setColorOutput(bool enable);

/**
 * @brief Print colored text (if enabled)
 * @param text Text to print
 * @param colorCode ANSI color code (e.g., "32" for green)
 */
void printColored(const std::string& text, const std::string& colorCode);

//=============================================================================
// Entry Points (defined in platform-specific files)
//=============================================================================

/**
 * @brief Main entry point for CLI mode
 * @param argc Argument count
 * @param argv Argument values
 * @return Exit code
 */
int cliMain(int argc, char* argv[]);

#ifdef _WIN32
/**
 * @brief Main entry point for Windows GUI mode
 * @param hInstance Application instance
 * @param lpCmdLine Command line
 * @param nCmdShow Show command
 * @return Exit code
 */
int guiMain(void* hInstance, const char* lpCmdLine, int nCmdShow);
#endif

} // namespace platform
} // namespace encrypt

#endif // ENCRYPT_PLATFORM_H
