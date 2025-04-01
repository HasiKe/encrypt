#ifndef ENCRYPT_PLATFORM_H
#define ENCRYPT_PLATFORM_H

#include <string>
#include <functional>

#include "encrypt/crypto.h" // For SecurityLevel

namespace encrypt {
namespace platform {

/**
 * @brief Shows a message to the user
 * 
 * @param message The message to display
 * @param title The title of the message (for dialog boxes)
 */
void showMessage(const std::string& message, const std::string& title = "Encryption");

/**
 * @brief Requests a password from the user
 * 
 * @param prompt Text for the password prompt
 * @return The entered password
 */
std::string getPassword(const std::string& prompt = "Please enter the password:");

/**
 * @brief Requests a password with confirmation from the user (for encryption)
 * 
 * @return The entered password
 */
std::string getPasswordWithConfirmation();

/**
 * @brief Requests the selection of a security level from the user
 * 
 * @return The selected security level
 */
SecurityLevel getSecurityLevel();

/**
 * @brief Shows a progress bar
 * 
 * @param progress Value between 0.0 and 1.0
 * @param operation Description of the operation
 */
void updateProgress(float progress, const std::string& operation);

/**
 * @brief Corrects path separators for the current operating system
 * 
 * @param path The path to correct
 * @return The corrected path
 */
std::string normalizePath(const std::string& path);

/**
 * @brief Extracts the filename from a path
 * 
 * @param path The full path
 * @return The filename without path
 */
std::string getFileName(const std::string& path);

/**
 * @brief Checks if a file exists
 * 
 * @param path Path to the file
 * @return true if the file exists, false otherwise
 */
bool fileExists(const std::string& path);

/**
 * @brief Determines if a path is a folder
 * 
 * @param path Path to check
 * @return true if the path is a folder, false otherwise
 */
bool isFolder(const std::string& path);

/**
 * @brief Determines if a file is an encrypted file (based on file extension)
 * 
 * @param path Path to the file
 * @return true if the file is encrypted (.cryp extension), false otherwise
 */
bool isEncryptedFile(const std::string& path);

/**
 * @brief Processes a file (encryption or decryption)
 * 
 * @param filePath Path to the file to process
 * @return true if successful, false on error
 */
bool processFile(const std::string& filePath);

} // namespace platform
} // namespace encrypt

#endif // ENCRYPT_PLATFORM_H