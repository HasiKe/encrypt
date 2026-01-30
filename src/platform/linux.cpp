/**
 * @file linux.cpp
 * @brief Linux/Unix platform implementation
 * @author HasiKe
 * @version 2.0.0
 * 
 * Provides platform-specific implementations for Linux and
 * other Unix-like systems using POSIX APIs.
 */

#include "encrypt/platform.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <termios.h>
#include <pwd.h>

namespace encrypt {
namespace platform {

//=============================================================================
// ANSI Codes
//=============================================================================

static bool g_colorEnabled = true;

namespace ansi {
    const char* RESET   = "\033[0m";
    const char* RED     = "\033[31m";
    const char* GREEN   = "\033[32m";
    const char* YELLOW  = "\033[33m";
    const char* BLUE    = "\033[34m";
    const char* CYAN    = "\033[36m";
    const char* BOLD    = "\033[1m";
}

//=============================================================================
// User Interaction
//=============================================================================

void showMessage(const std::string& message, const std::string& title,
                 bool isError) {
    std::ostream& out = isError ? std::cerr : std::cout;
    
    if (!title.empty()) {
        if (g_colorEnabled) {
            out << (isError ? ansi::RED : ansi::CYAN) << ansi::BOLD;
        }
        out << "[" << title << "] ";
        if (g_colorEnabled) out << ansi::RESET;
    }
    
    out << message << std::endl;
}

std::string getPassword(const std::string& prompt, bool confirm) {
    // Disable terminal echo
    struct termios oldTerm, newTerm;
    tcgetattr(STDIN_FILENO, &oldTerm);
    newTerm = oldTerm;
    newTerm.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newTerm);
    
    std::string password;
    std::string confirmPassword;
    
    std::cout << prompt;
    std::getline(std::cin, password);
    std::cout << std::endl;
    
    if (confirm) {
        std::cout << "Confirm password: ";
        std::getline(std::cin, confirmPassword);
        std::cout << std::endl;
        
        if (password != confirmPassword) {
            std::cerr << "Passwords do not match!" << std::endl;
            tcsetattr(STDIN_FILENO, TCSANOW, &oldTerm);
            return "";
        }
    }
    
    // Restore terminal
    tcsetattr(STDIN_FILENO, TCSANOW, &oldTerm);
    return password;
}

SecurityLevel getSecurityLevel() {
    std::cout << "Select security level:" << std::endl;
    
    for (int i = 1; i <= 5; ++i) {
        SecurityLevel lvl = static_cast<SecurityLevel>(i);
        std::cout << "  " << i << ". " 
                  << Crypto::getSecurityLevelDescription(lvl);
        if (i == 2) std::cout << " (recommended)";
        std::cout << std::endl;
    }
    
    std::cout << "Enter level [2]: ";
    std::string input;
    std::getline(std::cin, input);
    
    if (input.empty()) {
        return SecurityLevel::LEVEL_2;
    }
    
    int level = std::atoi(input.c_str());
    if (level < 1 || level > 5) {
        std::cout << "Invalid level, using default (2)" << std::endl;
        return SecurityLevel::LEVEL_2;
    }
    
    return static_cast<SecurityLevel>(level);
}

bool askConfirmation(const std::string& question, bool defaultYes) {
    std::cout << question << " [" << (defaultYes ? "Y/n" : "y/N") << "]: ";
    
    std::string input;
    std::getline(std::cin, input);
    
    if (input.empty()) {
        return defaultYes;
    }
    
    char c = std::tolower(input[0]);
    return c == 'y';
}

void showProgress(uint64_t current, uint64_t total, const std::string& message) {
    const int barWidth = 40;
    double progress = total > 0 ? (double)current / total : 0;
    int filled = static_cast<int>(progress * barWidth);
    int percent = static_cast<int>(progress * 100);
    
    std::cout << "\r  ";
    
    if (!message.empty()) {
        std::string displayMsg = message;
        if (displayMsg.length() > 20) {
            displayMsg = "..." + displayMsg.substr(displayMsg.length() - 17);
        }
        std::cout << std::setw(20) << std::left << displayMsg << " ";
    }
    
    std::cout << "[";
    if (g_colorEnabled) std::cout << ansi::CYAN;
    
    for (int i = 0; i < barWidth; ++i) {
        std::cout << (i < filled ? "█" : "░");
    }
    
    if (g_colorEnabled) std::cout << ansi::RESET;
    std::cout << "] " << std::setw(3) << percent << "%";
    std::cout.flush();
}

void clearProgress() {
    std::cout << "\r" << std::string(80, ' ') << "\r";
    std::cout.flush();
}

//=============================================================================
// File System Operations
//=============================================================================

std::string normalizePath(const std::string& path) {
    std::string normalized = path;
    
    // Remove trailing slashes
    while (normalized.length() > 1 && normalized.back() == '/') {
        normalized.pop_back();
    }
    
    // Expand ~ to home directory
    if (!normalized.empty() && normalized[0] == '~') {
        const char* home = getenv("HOME");
        if (!home) {
            struct passwd* pw = getpwuid(getuid());
            if (pw) home = pw->pw_dir;
        }
        if (home) {
            normalized = std::string(home) + normalized.substr(1);
        }
    }
    
    return normalized;
}

bool fileExists(const std::string& path) {
    struct stat st;
    return stat(normalizePath(path).c_str(), &st) == 0;
}

bool isDirectory(const std::string& path) {
    struct stat st;
    if (stat(normalizePath(path).c_str(), &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

uint64_t getFileSize(const std::string& path) {
    struct stat st;
    if (stat(normalizePath(path).c_str(), &st) != 0) {
        return 0;
    }
    return static_cast<uint64_t>(st.st_size);
}

std::string getFilename(const std::string& path) {
    size_t pos = path.find_last_of('/');
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

std::string getDirectory(const std::string& path) {
    size_t pos = path.find_last_of('/');
    if (pos == std::string::npos) {
        return ".";
    }
    if (pos == 0) {
        return "/";
    }
    return path.substr(0, pos);
}

std::string getExtension(const std::string& path) {
    std::string filename = getFilename(path);
    size_t pos = filename.find_last_of('.');
    if (pos == std::string::npos || pos == 0) {
        return "";
    }
    return filename.substr(pos);
}

std::string removeExtension(const std::string& path) {
    std::string ext = getExtension(path);
    if (ext.empty()) {
        return path;
    }
    return path.substr(0, path.length() - ext.length());
}

bool createDirectory(const std::string& path) {
    std::string normalized = normalizePath(path);
    
    // Create parent directories if needed
    for (size_t i = 1; i < normalized.length(); ++i) {
        if (normalized[i] == '/') {
            std::string subpath = normalized.substr(0, i);
            if (!fileExists(subpath)) {
                if (mkdir(subpath.c_str(), 0755) != 0 && errno != EEXIST) {
                    return false;
                }
            }
        }
    }
    
    // Create the final directory
    if (!fileExists(normalized)) {
        return mkdir(normalized.c_str(), 0755) == 0;
    }
    return true;
}

std::vector<std::string> listFiles(const std::string& path, bool recursive) {
    std::vector<std::string> files;
    std::string normalized = normalizePath(path);
    
    DIR* dir = opendir(normalized.c_str());
    if (!dir) {
        return files;
    }
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") {
            continue;
        }
        
        std::string fullPath = normalized + "/" + name;
        
        if (isDirectory(fullPath)) {
            if (recursive) {
                auto subFiles = listFiles(fullPath, true);
                files.insert(files.end(), subFiles.begin(), subFiles.end());
            }
        } else {
            files.push_back(fullPath);
        }
    }
    
    closedir(dir);
    return files;
}

bool deleteFile(const std::string& path) {
    return unlink(normalizePath(path).c_str()) == 0;
}

std::string getTempDirectory() {
    const char* tmpdir = getenv("TMPDIR");
    if (tmpdir) return tmpdir;
    
    tmpdir = getenv("TMP");
    if (tmpdir) return tmpdir;
    
    tmpdir = getenv("TEMP");
    if (tmpdir) return tmpdir;
    
    return "/tmp";
}

std::string getTempFilename(const std::string& prefix) {
    std::string path = getTempDirectory() + "/" + prefix + "XXXXXX";
    
    // Create a copy for mkstemp (it modifies the string)
    std::vector<char> buffer(path.begin(), path.end());
    buffer.push_back('\0');
    
    int fd = mkstemp(buffer.data());
    if (fd >= 0) {
        close(fd);
        return std::string(buffer.data());
    }
    
    // Fallback
    return getTempDirectory() + "/" + prefix + std::to_string(getpid());
}

//=============================================================================
// High-Level Operations
//=============================================================================

EncryptionResult processFile(const std::string& inputPath,
                             const std::string& password,
                             SecurityLevel level) {
    std::string normalized = normalizePath(inputPath);
    
    // Check if file exists
    if (!fileExists(normalized)) {
        EncryptionResult result;
        result.success = false;
        result.errorMessage = "File not found: " + normalized;
        return result;
    }
    
    // Get password if not provided
    std::string pwd = password;
    if (pwd.empty()) {
        bool isEncrypted = getExtension(normalized) == Constants::ENCRYPTED_EXTENSION;
        pwd = getPassword(isEncrypted ? "Enter password: " : "Enter password: ",
                          !isEncrypted);
        if (pwd.empty()) {
            EncryptionResult result;
            result.success = false;
            result.errorMessage = "Password required";
            return result;
        }
    }
    
    // Determine operation mode
    bool decrypt = false;
    if (getExtension(normalized) == Constants::ENCRYPTED_EXTENSION) {
        decrypt = true;
    } else if (Crypto::isEncryptedFile(normalized)) {
        decrypt = true;
    }
    
    // Progress callback
    ProgressCallback progress = [](uint64_t current, uint64_t total,
                                   const std::string& filename) -> bool {
        showProgress(current, total, filename);
        return true;
    };
    
    // Execute operation
    EncryptionResult result;
    
    if (decrypt) {
        auto header = Crypto::readFileHeader(normalized);
        if (header.isFolder) {
            result = Crypto::decryptFolder(normalized, pwd, "", progress);
        } else {
            result = Crypto::decryptFile(normalized, pwd, "", progress);
        }
    } else {
        // Get security level if using default
        SecurityLevel lvl = level;
        if (lvl == SecurityLevel::LEVEL_1) {
            lvl = getSecurityLevel();
        }
        
        if (isDirectory(normalized)) {
            result = Crypto::encryptFolder(normalized, pwd, lvl, "", progress);
        } else {
            result = Crypto::encryptFile(normalized, pwd, lvl, "", progress);
        }
    }
    
    clearProgress();
    return result;
}

std::vector<EncryptionResult> processFiles(const std::vector<std::string>& paths,
                                           const std::string& password,
                                           SecurityLevel level) {
    std::vector<EncryptionResult> results;
    
    for (const auto& path : paths) {
        results.push_back(processFile(path, password, level));
    }
    
    return results;
}

//=============================================================================
// System Utilities
//=============================================================================

std::string getPlatformName() {
#if defined(__linux__)
    return "Linux";
#elif defined(__APPLE__)
    return "macOS";
#elif defined(__FreeBSD__)
    return "FreeBSD";
#else
    return "Unix";
#endif
}

bool isGuiAvailable() {
    // Check for display environment variable
    return getenv("DISPLAY") != nullptr || getenv("WAYLAND_DISPLAY") != nullptr;
}

std::string getCurrentDirectory() {
    char buffer[4096];
    if (getcwd(buffer, sizeof(buffer))) {
        return std::string(buffer);
    }
    return ".";
}

void setConsoleTitle(const std::string& title) {
    // ANSI escape sequence for terminal title
    std::cout << "\033]0;" << title << "\007" << std::flush;
}

void clearScreen() {
    std::cout << "\033[2J\033[H" << std::flush;
}

void setColorOutput(bool enable) {
    g_colorEnabled = enable;
}

void printColored(const std::string& text, const std::string& colorCode) {
    if (g_colorEnabled) {
        std::cout << "\033[" << colorCode << "m" << text << ansi::RESET;
    } else {
        std::cout << text;
    }
}

} // namespace platform
} // namespace encrypt
