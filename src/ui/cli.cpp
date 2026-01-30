/**
 * @file cli.cpp
 * @brief Command-line interface implementation
 * @author HasiKe
 * @version 2.0.0
 * 
 * Provides command-line argument parsing, help display,
 * and interactive password strength checker.
 */

#include "encrypt/crypto.h"
#include "encrypt/platform.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <chrono>

namespace encrypt {
namespace platform {

//=============================================================================
// ANSI Color Codes
//=============================================================================

namespace Color {
    const char* RESET   = "\033[0m";
    const char* RED     = "\033[31m";
    const char* GREEN   = "\033[32m";
    const char* YELLOW  = "\033[33m";
    const char* BLUE    = "\033[34m";
    const char* MAGENTA = "\033[35m";
    const char* CYAN    = "\033[36m";
    const char* BOLD    = "\033[1m";
    const char* DIM     = "\033[2m";
}

static bool g_useColors = true;

//=============================================================================
// Helper Functions
//=============================================================================

static void printLogo() {
    if (g_useColors) {
        std::cout << Color::CYAN << Color::BOLD;
    }
    std::cout << R"(
   ___                       _   
  / _ \_ __   ___ _ __ _   _| |_ 
 / /_)/ '_ \ / __| '__| | | | __|
/ ___/| | | | (__| |  | |_| | |_ 
\/    |_| |_|\___|_|   \__, |\__|
                       |___/     
)" << std::endl;
    
    if (g_useColors) {
        std::cout << Color::RESET << Color::DIM;
    }
    std::cout << "  Military-grade file encryption v" 
              << Crypto::getVersion() << std::endl;
    if (g_useColors) {
        std::cout << Color::RESET;
    }
    std::cout << std::endl;
}

static void printHelp(const char* programName) {
    printLogo();
    
    std::cout << "USAGE:" << std::endl;
    std::cout << "  " << programName << " [OPTIONS] <file|folder>" << std::endl;
    std::cout << std::endl;
    
    std::cout << "OPTIONS:" << std::endl;
    std::cout << "  -h, --help          Show this help message" << std::endl;
    std::cout << "  -v, --version       Show version information" << std::endl;
    std::cout << "  -d, --decrypt       Decrypt mode (auto-detected if .cryp)" << std::endl;
    std::cout << "  -l, --level <1-5>   Security level (default: 2)" << std::endl;
    std::cout << "  -p, --password <pw> Password (will prompt if not given)" << std::endl;
    std::cout << "  -o, --output <path> Output path" << std::endl;
    std::cout << "  -c, --check         Interactive password strength checker" << std::endl;
    std::cout << "  -q, --quiet         Suppress progress output" << std::endl;
    std::cout << "  --no-color          Disable colored output" << std::endl;
    std::cout << std::endl;
    
    std::cout << "SECURITY LEVELS:" << std::endl;
    for (int i = 1; i <= 5; ++i) {
        SecurityLevel lvl = static_cast<SecurityLevel>(i);
        std::cout << "  " << i << " - " 
                  << Crypto::getSecurityLevelDescription(lvl) << std::endl;
    }
    std::cout << std::endl;
    
    std::cout << "EXAMPLES:" << std::endl;
    std::cout << "  " << programName << " document.pdf          # Encrypt with Level 2" << std::endl;
    std::cout << "  " << programName << " -l 5 secret.docx      # Maximum security" << std::endl;
    std::cout << "  " << programName << " -l 3 my_folder/       # Encrypt folder" << std::endl;
    std::cout << "  " << programName << " -d document.pdf.cryp  # Decrypt" << std::endl;
    std::cout << "  " << programName << " document.pdf.cryp     # Auto-detect decrypt" << std::endl;
    std::cout << "  " << programName << " -c                    # Password checker" << std::endl;
    std::cout << std::endl;
}

static void printVersion() {
    std::cout << "Encrypt v" << Crypto::getVersion() << std::endl;
    std::cout << "Copyright (c) 2026 HasiKe" << std::endl;
    std::cout << "License: MIT" << std::endl;
    std::cout << "Platform: " << getPlatformName() << std::endl;
}

static void printStrengthBar(int score) {
    const int barWidth = 30;
    int filled = (score * barWidth) / 100;
    
    const char* color;
    if (score >= Constants::PASSWORD_STRENGTH_STRONG) {
        color = Color::GREEN;
    } else if (score >= Constants::PASSWORD_STRENGTH_GOOD) {
        color = Color::CYAN;
    } else if (score >= Constants::PASSWORD_STRENGTH_FAIR) {
        color = Color::YELLOW;
    } else {
        color = Color::RED;
    }
    
    std::cout << "  [";
    if (g_useColors) std::cout << color;
    
    for (int i = 0; i < barWidth; ++i) {
        if (i < filled) {
            std::cout << "█";
        } else {
            std::cout << "░";
        }
    }
    
    if (g_useColors) std::cout << Color::RESET;
    std::cout << "] " << score << "%" << std::endl;
}

static void runPasswordChecker() {
    printLogo();
    std::cout << "Interactive Password Strength Checker" << std::endl;
    std::cout << "Enter passwords to test (empty line to exit)" << std::endl;
    std::cout << std::endl;
    
    while (true) {
        std::string password = getPassword("Test password: ", false);
        
        if (password.empty()) {
            std::cout << "Exiting password checker." << std::endl;
            break;
        }
        
        auto analysis = Crypto::checkPasswordStrength(password);
        
        std::cout << std::endl;
        std::cout << "  Strength: ";
        
        const char* strengthColor;
        const char* strengthText;
        
        switch (analysis.strength) {
            case PasswordStrength::STRONG:
                strengthColor = Color::GREEN;
                strengthText = "STRONG";
                break;
            case PasswordStrength::GOOD:
                strengthColor = Color::CYAN;
                strengthText = "GOOD";
                break;
            case PasswordStrength::FAIR:
                strengthColor = Color::YELLOW;
                strengthText = "FAIR";
                break;
            case PasswordStrength::WEAK:
                strengthColor = Color::RED;
                strengthText = "WEAK";
                break;
            default:
                strengthColor = Color::RED;
                strengthText = "VERY WEAK";
                break;
        }
        
        if (g_useColors) std::cout << Color::BOLD << strengthColor;
        std::cout << strengthText;
        if (g_useColors) std::cout << Color::RESET;
        std::cout << std::endl;
        
        printStrengthBar(analysis.score);
        
        std::cout << std::endl;
        std::cout << "  Criteria:" << std::endl;
        
        auto printCriteria = [](const char* name, bool met) {
            if (g_useColors) {
                std::cout << (met ? Color::GREEN : Color::RED);
            }
            std::cout << "    " << (met ? "✓" : "✗") << " " << name;
            if (g_useColors) std::cout << Color::RESET;
            std::cout << std::endl;
        };
        
        printCriteria("Minimum length (8+ chars)", analysis.hasSufficientLength);
        printCriteria("Lowercase letters", analysis.hasLowercase);
        printCriteria("Uppercase letters", analysis.hasUppercase);
        printCriteria("Numbers", analysis.hasDigits);
        printCriteria("Special characters", analysis.hasSpecial);
        
        std::cout << std::endl;
        std::cout << "  " << analysis.feedback << std::endl;
        std::cout << std::endl;
    }
}

static void printProgressBar(uint64_t current, uint64_t total, 
                             const std::string& filename) {
    const int barWidth = 40;
    double progress = total > 0 ? (double)current / total : 0;
    int filled = static_cast<int>(progress * barWidth);
    int percent = static_cast<int>(progress * 100);
    
    std::cout << "\r";
    
    // Truncate filename if too long
    std::string displayName = filename;
    if (displayName.length() > 20) {
        displayName = "..." + displayName.substr(displayName.length() - 17);
    }
    
    std::cout << "  " << std::setw(20) << std::left << displayName << " [";
    
    if (g_useColors) std::cout << Color::CYAN;
    for (int i = 0; i < barWidth; ++i) {
        if (i < filled) {
            std::cout << "█";
        } else {
            std::cout << "░";
        }
    }
    if (g_useColors) std::cout << Color::RESET;
    
    std::cout << "] " << std::setw(3) << percent << "%";
    std::cout.flush();
}

//=============================================================================
// CLI Main Entry Point
//=============================================================================

int cliMain(int argc, char* argv[]) {
    // Parse arguments
    std::string inputPath;
    std::string outputPath;
    std::string password;
    SecurityLevel level = SecurityLevel::LEVEL_2;
    bool decrypt = false;
    bool quiet = false;
    bool checkMode = false;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            printHelp(argv[0]);
            return 0;
        }
        else if (arg == "-v" || arg == "--version") {
            printVersion();
            return 0;
        }
        else if (arg == "-d" || arg == "--decrypt") {
            decrypt = true;
        }
        else if (arg == "-c" || arg == "--check") {
            checkMode = true;
        }
        else if (arg == "-q" || arg == "--quiet") {
            quiet = true;
        }
        else if (arg == "--no-color") {
            g_useColors = false;
        }
        else if ((arg == "-l" || arg == "--level") && i + 1 < argc) {
            int lvl = std::atoi(argv[++i]);
            if (lvl < 1 || lvl > 5) {
                std::cerr << "Error: Security level must be 1-5" << std::endl;
                return 1;
            }
            level = static_cast<SecurityLevel>(lvl);
        }
        else if ((arg == "-p" || arg == "--password") && i + 1 < argc) {
            password = argv[++i];
        }
        else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            outputPath = argv[++i];
        }
        else if (arg[0] != '-') {
            inputPath = arg;
        }
        else {
            std::cerr << "Unknown option: " << arg << std::endl;
            std::cerr << "Use -h for help" << std::endl;
            return 1;
        }
    }
    
    // Password checker mode
    if (checkMode) {
        runPasswordChecker();
        return 0;
    }
    
    // Require input file for normal operation
    if (inputPath.empty()) {
        printHelp(argv[0]);
        return 1;
    }
    
    // Check if file exists
    if (!fileExists(inputPath)) {
        std::cerr << "Error: File not found: " << inputPath << std::endl;
        return 1;
    }
    
    // Auto-detect decrypt mode from extension
    if (!decrypt && getExtension(inputPath) == Constants::ENCRYPTED_EXTENSION) {
        decrypt = true;
    }
    
    // Get password if not provided
    if (password.empty()) {
        password = getPassword(decrypt ? "Enter password: " : "Enter password: ", 
                               !decrypt);  // Confirm for encryption
        if (password.empty()) {
            std::cerr << "Error: Password required" << std::endl;
            return 1;
        }
    }
    
    // Check password strength for encryption
    if (!decrypt) {
        auto analysis = Crypto::checkPasswordStrength(password);
        if (analysis.strength == PasswordStrength::VERY_WEAK) {
            if (g_useColors) std::cout << Color::YELLOW;
            std::cout << "Warning: Very weak password detected!" << std::endl;
            if (g_useColors) std::cout << Color::RESET;
            std::cout << analysis.feedback << std::endl;
            
            if (!askConfirmation("Continue anyway?", false)) {
                return 1;
            }
        }
    }
    
    // Progress callback
    ProgressCallback progress = nullptr;
    if (!quiet) {
        progress = [](uint64_t current, uint64_t total, 
                      const std::string& filename) -> bool {
            printProgressBar(current, total, filename);
            return true;  // Continue processing
        };
    }
    
    // Perform operation
    if (!quiet) {
        printLogo();
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    EncryptionResult result;
    bool isFolder = isDirectory(inputPath);
    
    if (decrypt) {
        if (!quiet) {
            std::cout << "Decrypting: " << inputPath << std::endl;
        }
        
        // Check if it's a folder archive
        auto header = Crypto::readFileHeader(inputPath);
        if (header.isFolder) {
            result = Crypto::decryptFolder(inputPath, password, outputPath, progress);
        } else {
            result = Crypto::decryptFile(inputPath, password, outputPath, progress);
        }
    }
    else {
        if (!quiet) {
            std::cout << "Encrypting: " << inputPath << std::endl;
            std::cout << "Security Level: " << static_cast<int>(level)
                      << " (" << Crypto::getSecurityLevelDescription(level) << ")"
                      << std::endl;
        }
        
        if (isFolder) {
            result = Crypto::encryptFolder(inputPath, password, level, 
                                           outputPath, progress);
        } else {
            result = Crypto::encryptFile(inputPath, password, level, 
                                         outputPath, progress);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();
    
    if (!quiet) {
        std::cout << std::endl;
    }
    
    // Print result
    if (result.success) {
        if (!quiet) {
            if (g_useColors) std::cout << Color::GREEN;
            std::cout << "✓ " << (decrypt ? "Decryption" : "Encryption") 
                      << " complete!" << std::endl;
            if (g_useColors) std::cout << Color::RESET;
            
            std::cout << "  Output: " << result.outputPath << std::endl;
            std::cout << "  Time: " << std::fixed << std::setprecision(2) 
                      << elapsed << "s" << std::endl;
            
            double mbps = (result.bytesProcessed / 1048576.0) / elapsed;
            std::cout << "  Speed: " << std::fixed << std::setprecision(1) 
                      << mbps << " MB/s" << std::endl;
        }
        return 0;
    }
    else {
        if (g_useColors) std::cerr << Color::RED;
        std::cerr << "✗ " << (decrypt ? "Decryption" : "Encryption") 
                  << " failed!" << std::endl;
        if (g_useColors) std::cerr << Color::RESET;
        
        std::cerr << "  Error: " << result.errorMessage << std::endl;
        return 1;
    }
}

} // namespace platform
} // namespace encrypt
