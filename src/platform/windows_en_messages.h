#ifndef ENCRYPT_WINDOWS_EN_MESSAGES_H
#define ENCRYPT_WINDOWS_EN_MESSAGES_H

// English messages for Windows UI

namespace encrypt {
namespace platform {

// Window title
constexpr const char* WINDOW_TITLE = "Encrypt - Secure File and Folder Encryption";

// Drag-and-drop instructions
constexpr const char* DRAG_DROP_INSTRUCTIONS = 
    "Drag files or folders here to encrypt or decrypt them.\n\n"
    "Files with .cryp extension will be decrypted,\n"
    "all other files or folders will be encrypted.";

// Dialog messages
constexpr const char* MSG_ERROR_TITLE = "Error";
constexpr const char* MSG_SUCCESS_TITLE = "Success";
constexpr const char* MSG_WARNING_TITLE = "Warning";
constexpr const char* MSG_CANCEL_TITLE = "Canceled";

constexpr const char* MSG_NO_PASSWORD = "No password provided. Operation canceled.";
constexpr const char* MSG_PASSWORD_MISMATCH = "Passwords do not match!";
constexpr const char* MSG_REGISTER_CLASS_FAILED = "Window class registration failed.";
constexpr const char* MSG_CREATE_WINDOW_FAILED = "Window creation failed.";

// Success messages
constexpr const char* MSG_DECRYPTION_SUCCESS = "File/folder successfully decrypted.";
constexpr const char* MSG_FOLDER_ENCRYPTION_SUCCESS_PREFIX = "Folder successfully encrypted with security level ";
constexpr const char* MSG_FILE_ENCRYPTION_SUCCESS_PREFIX = "File successfully encrypted with security level ";

// Progress messages
constexpr const char* PROGRESS_ENCRYPT_FILE = "Encrypting file";
constexpr const char* PROGRESS_ENCRYPT_FOLDER = "Encrypting folder";
constexpr const char* PROGRESS_DECRYPT = "Decrypting file/folder";

} // namespace platform
} // namespace encrypt

#endif // ENCRYPT_WINDOWS_EN_MESSAGES_H