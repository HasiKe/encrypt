#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>

#include "encrypt/crypto.h"
#include "encrypt/platform.h"

namespace encrypt {
namespace ui {

/**
 * @brief Displays the program help
 */
void printHelp() {
    std::cout << "Usage: encrypt [options] <file>" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help              Show this help" << std::endl;
    std::cout << "  -d, --decrypt           Decrypt file (default: encrypt)" << std::endl;
    std::cout << "  -o, --output <file>     Specify output file" << std::endl;
    std::cout << "  -p, --password <pass>   Specify password (INSECURE, better interactive!)" << std::endl;
    std::cout << "  -l, --level <1-5>       Specify security level (1=fast, 5=max. secure)" << std::endl;
    std::cout << "  -c, --check-password    Check password strength without encryption" << std::endl;
    std::cout << std::endl;
    std::cout << "Security levels:" << std::endl;
    std::cout << "  1: Fast, good for non-critical data (AES-128-GCM, PBKDF2 with 10,000 iterations)" << std::endl;
    std::cout << "  2: Balanced, default (AES-256-GCM, PBKDF2 with 100,000 iterations)" << std::endl;
    std::cout << "  3: Enhanced security (AES-256-GCM, PBKDF2 with 250,000 iterations)" << std::endl;
    std::cout << "  4: High security (AES-256-GCM, Argon2id with 64MB RAM)" << std::endl;
    std::cout << "  5: Maximum security (AES-256-GCM + ChaCha20, Argon2id with 256MB RAM)" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  encrypt myDocument.docx               # Encrypts the file with default security" << std::endl;
    std::cout << "  encrypt -l 4 myDocument.docx          # Encrypts with high security" << std::endl;
    std::cout << "  encrypt -d myDocument.docx.cryp       # Decrypts the file" << std::endl;
    std::cout << "  encrypt -c                            # Interactive password check" << std::endl;
}

/**
 * @brief Displays the password strength evaluation
 */
void displayPasswordStrength(const std::string& password) {
    int strength = Crypto::checkPasswordStrength(password);
    
    // Determine the category
    std::string category;
    if (strength < 20) category = "Very weak";
    else if (strength < 40) category = "Weak";
    else if (strength < 60) category = "Medium";
    else if (strength < 80) category = "Strong";
    else category = "Very strong";
    
    // Determine the color (ANSI escape sequences)
    std::string colorStart, colorEnd = "\033[0m";
    if (strength < 20) colorStart = "\033[1;31m"; // Red, bold
    else if (strength < 40) colorStart = "\033[0;31m"; // Red
    else if (strength < 60) colorStart = "\033[0;33m"; // Yellow
    else if (strength < 80) colorStart = "\033[0;32m"; // Green
    else colorStart = "\033[1;32m"; // Green, bold
    
    // Create progress bar
    const int barWidth = 30;
    int filledWidth = barWidth * strength / 100;
    
    std::cout << "Password strength: " << colorStart << strength << "/100 (" << category << ")" << colorEnd << std::endl;
    
    // Bar representation
    std::cout << "[";
    for (int i = 0; i < barWidth; ++i) {
        if (i < filledWidth) {
            std::cout << colorStart << "=" << colorEnd;
        } else {
            std::cout << " ";
        }
    }
    std::cout << "]" << std::endl;
    
    // Recommendations
    if (strength < 60) {
        std::cout << "\nRecommendations for improvement:" << std::endl;
        if (password.length() < 12) {
            std::cout << "- Use a longer password (at least 12 characters)" << std::endl;
        }
        
        bool hasLower = std::any_of(password.begin(), password.end(), [](char c) { return islower(c); });
        bool hasUpper = std::any_of(password.begin(), password.end(), [](char c) { return isupper(c); });
        bool hasDigit = std::any_of(password.begin(), password.end(), [](char c) { return isdigit(c); });
        bool hasSpecial = std::any_of(password.begin(), password.end(), [](char c) { return !isalnum(c); });
        
        if (!hasLower) std::cout << "- Add lowercase letters" << std::endl;
        if (!hasUpper) std::cout << "- Add uppercase letters" << std::endl;
        if (!hasDigit) std::cout << "- Add numbers" << std::endl;
        if (!hasSpecial) std::cout << "- Add special characters" << std::endl;
    }
}

/**
 * @brief Interactive password check
 */
void interactivePasswordCheck() {
    std::cout << "=== Password Strength Check ===" << std::endl;
    std::cout << "Enter a password (or an empty line to exit):" << std::endl;
    
    while (true) {
        std::string password = platform::getPassword("Password: ");
        if (password.empty()) {
            break;
        }
        
        displayPasswordStrength(password);
        std::cout << "\nEnter a new password (or empty to exit):" << std::endl;
    }
}

/**
 * @brief Main function for CLI
 * 
 * @param argc Number of arguments
 * @param argv Argument values
 * @return int Program return value
 */
int run(int argc, char* argv[]) {
    if (argc < 2) {
        printHelp();
        return 1;
    }
    
    // Default values
    bool decrypt = false;
    bool checkPasswordMode = false;
    std::string inputFile;
    std::string outputFile;
    std::string password;
    SecurityLevel level = SecurityLevel::LEVEL_2; // Default level
    
    // Process arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            printHelp();
            return 0;
        } else if (arg == "-d" || arg == "--decrypt") {
            decrypt = true;
        } else if (arg == "-c" || arg == "--check-password") {
            checkPasswordMode = true;
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            outputFile = argv[++i];
        } else if ((arg == "-p" || arg == "--password") && i + 1 < argc) {
            password = argv[++i];
        } else if ((arg == "-l" || arg == "--level") && i + 1 < argc) {
            int levelValue = std::atoi(argv[++i]);
            if (levelValue < 1 || levelValue > 5) {
                platform::showMessage("Invalid security level. Please specify a value between 1 and 5.", "Error");
                return 1;
            }
            level = static_cast<SecurityLevel>(levelValue);
        } else if (arg[0] == '-') {
            platform::showMessage("Unknown option: " + arg, "Error");
            return 1;
        } else {
            // File name (without option)
            inputFile = arg;
        }
    }
    
    // Password check mode
    if (checkPasswordMode) {
        interactivePasswordCheck();
        return 0;
    }
    
    // Check if input file was specified (except in password check mode)
    if (inputFile.empty()) {
        platform::showMessage("No input file specified!", "Error");
        return 1;
    }
    
    // Check if file exists
    if (!platform::fileExists(inputFile)) {
        platform::showMessage("File does not exist: " + inputFile, "Error");
        return 1;
    }
    
    // Determine default output file if not specified
    if (outputFile.empty()) {
        if (decrypt) {
            // For decryption, the name is read from the file
            // Output filename will be determined later
        } else {
            outputFile = inputFile + ".cryp";
        }
    }
    
    // Interactively query password if not specified
    if (password.empty()) {
        password = platform::getPassword();
        
        // Second input for confirmation when encrypting
        if (!decrypt) {
            std::string confirmPassword = platform::getPassword("Repeat password: ");
            if (password != confirmPassword) {
                platform::showMessage("Passwords do not match!", "Error");
                return 1;
            }
        }
        
        if (password.empty()) {
            platform::showMessage("No password specified. Operation cancelled.", "Cancelled");
            return 1;
        }
    }
    
    // Check password strength for encryption
    if (!decrypt) {
        int passwordStrength = Crypto::checkPasswordStrength(password);
        
        if (passwordStrength < 40) {
            std::string message = "Warning: Weak password (strength: " + 
                                std::to_string(passwordStrength) + "/100)\n" +
                                "Do you want to continue anyway? (y/n): ";
                                
            std::cout << message;
            char response;
            std::cin >> response;
            
            if (response != 'y' && response != 'Y') {
                platform::showMessage("Operation cancelled.", "Cancelled");
                return 1;
            }
        }
    }
    
    // Progress display callback
    auto progressCallback = [decrypt](float progress) {
        platform::updateProgress(progress, decrypt ? "Decrypting file" : "Encrypting file");
    };
    
    // Perform encryption or decryption
    bool success = false;
    
    try {
        // After the encryption test was successful, we can now use file encryption
        std::cerr << "Starting file encryption" << std::endl;
        
        if (decrypt) {
            success = Crypto::decryptFile(inputFile, password, outputFile, progressCallback);
        } else {
            success = Crypto::encryptFile(inputFile, outputFile, password, level, progressCallback);
        }
    } catch (const std::exception& e) {
        std::cerr << "EXCEPTION: " << e.what() << std::endl;
        platform::showMessage(std::string("Exception error: ") + e.what(), "Error");
        return 1;
    } catch (...) {
        std::cerr << "UNKNOWN EXCEPTION" << std::endl;
        platform::showMessage("Unknown exception error", "Error");
        return 1;
    }
    
    // Display result
    if (success) {
        std::string message = decrypt 
            ? "File successfully decrypted."
            : "File successfully encrypted with security level " + std::to_string(static_cast<int>(level)) + ".";
        platform::showMessage(message, "Success");
        return 0;
    } else {
        platform::showMessage("Error: " + Crypto::getLastError(), "Error");
        return 1;
    }
}

} // namespace ui
} // namespace encrypt