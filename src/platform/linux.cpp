#include "encrypt/platform.h"

#ifndef _WIN32

#include <iostream>
#include <string>
#include <filesystem>
#include <termios.h>
#include <unistd.h>
#include <cstring>
#include <sys/stat.h>

namespace encrypt {
namespace platform {

// Hilfsfunktion zum Deaktivieren der Anzeige von Zeichen im Terminal
void setStdinEcho(bool enable) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

void showMessage(const std::string& message, const std::string& title) {
    std::cout << "=== " << title << " ===" << std::endl;
    std::cout << message << std::endl;
}

std::string getPassword(const std::string& prompt) {
    std::string password;
    
    std::cout << prompt << " ";
    
    // Deaktiviere Anzeige von eingegebenen Zeichen
    setStdinEcho(false);
    
    // Passwort einlesen
    std::getline(std::cin, password);
    
    // Anzeige wieder aktivieren
    setStdinEcho(true);
    
    // Zeilenumbruch für bessere Lesbarkeit
    std::cout << std::endl;
    
    return password;
}

std::string getPasswordWithConfirmation() {
    std::string password = getPassword();
    std::string confirmPassword = getPassword("Passwort wiederholen: ");
    
    if (password != confirmPassword) {
        std::cout << "Die Passwörter stimmen nicht überein!" << std::endl;
        return "";
    }
    
    return password;
}

SecurityLevel getSecurityLevel() {
    std::cout << "Bitte Sicherheitsstufe wählen:" << std::endl;
    std::cout << "1) Schnell (AES-128, schnell aber weniger sicher)" << std::endl;
    std::cout << "2) Standard (AES-256, gute Balance)" << std::endl;
    std::cout << "3) Erhöhte Sicherheit (AES-256 mit mehr Iterationen)" << std::endl;
    std::cout << "4) Hohe Sicherheit (AES-256 mit Argon2)" << std::endl;
    std::cout << "5) Maximale Sicherheit (AES-256 + ChaCha20, sehr langsam)" << std::endl;
    
    int level = 0;
    while (level < 1 || level > 5) {
        std::cout << "Wählen Sie eine Stufe (1-5) [Standard: 2]: ";
        std::string input;
        std::getline(std::cin, input);
        
        if (input.empty()) {
            level = 2; // Standardwert
            break;
        }
        
        try {
            level = std::stoi(input);
        } catch (...) {
            level = 0;
        }
        
        if (level < 1 || level > 5) {
            std::cout << "Ungültige Eingabe. Bitte wählen Sie eine Stufe zwischen 1 und 5." << std::endl;
        }
    }
    
    return static_cast<SecurityLevel>(level);
}

// Globale Variablen für die Fortschrittsanzeige
int lastProgressDisplay = -1;
std::string currentOperation;

void updateProgress(float progress, const std::string& operation) {
    if (operation != currentOperation) {
        std::cout << operation << ":" << std::endl;
        currentOperation = operation;
    }
    
    // Fortschritt in Prozent umrechnen
    int percent = static_cast<int>(progress * 100);
    
    // Nur aktualisieren, wenn sich der Wert geändert hat
    if (percent != lastProgressDisplay) {
        // Fortschrittsbalken
        const int barWidth = 50;
        int pos = static_cast<int>(barWidth * progress);
        
        std::cout << "[";
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) std::cout << "=";
            else if (i == pos) std::cout << ">";
            else std::cout << " ";
        }
        
        std::cout << "] " << percent << " %\r";
        std::cout.flush();
        
        lastProgressDisplay = percent;
        
        // Bei 100% neue Zeile ausgeben
        if (percent == 100) {
            std::cout << std::endl;
        }
    }
}

std::string normalizePath(const std::string& path) {
    std::string result = path;
    
    // Ersetze "\" durch "/"
    for (char& c : result) {
        if (c == '\\') {
            c = '/';
        }
    }
    
    return result;
}

std::string getFileName(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    if (pos != std::string::npos) {
        return path.substr(pos + 1);
    }
    return path;
}

bool fileExists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0 && S_ISREG(buffer.st_mode));
}

bool isFolder(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0 && S_ISDIR(buffer.st_mode));
}

bool isEncryptedFile(const std::string& path) {
    size_t pos = path.find_last_of('.');
    if (pos != std::string::npos) {
        std::string extension = path.substr(pos);
        return (extension == ".cryp");
    }
    return false;
}

bool processFile(const std::string& filePath) {
    bool isEncrypted = isEncryptedFile(filePath);
    bool isDirectory = isFolder(filePath);
    
    // Bestimme den Ausgabepfad
    std::string outputPath;
    if (isEncrypted) {
        // Bei verschlüsselten Dateien wird der Name beim Entschlüsseln automatisch bestimmt
        outputPath = "";
    } else {
        // Bei unverschlüsselten Dateien/Ordnern fügen wir .cryp hinzu
        outputPath = filePath + ".cryp";
    }
    
    // Hole das Passwort
    std::string password;
    if (isEncrypted) {
        // Für Entschlüsselung benötigen wir keine Passwortbestätigung
        password = getPassword();
    } else {
        // Für Verschlüsselung benötigen wir eine Passwortbestätigung
        password = getPasswordWithConfirmation();
    }
    
    if (password.empty()) {
        showMessage("Kein Passwort angegeben. Vorgang abgebrochen.", "Abbruch");
        return false;
    }
    
    // Bei Verschlüsselung: Frage nach Sicherheitsstufe
    SecurityLevel level = SecurityLevel::LEVEL_2;
    if (!isEncrypted) {
        level = getSecurityLevel();
    }
    
    // Ver- oder Entschlüsselung durchführen
    bool success = false;
    try {
        // Unterschiedliche Behandlung für Dateien und Ordner
        if (isDirectory && !isEncrypted) {
            // Verschlüssele einen Ordner
            auto progressCallback = [](float progress) {
                updateProgress(progress, "Verschlüssele Ordner");
            };
            
            success = Crypto::encryptFolder(filePath, outputPath, password, level, progressCallback);
        } else if (isEncrypted) {
            // Entschlüssele eine Datei (könnte ein verschlüsselter Ordner sein)
            auto progressCallback = [](float progress) {
                updateProgress(progress, "Entschlüssele Datei/Ordner");
            };
            
            // Versuche zuerst als Ordner zu entschlüsseln
            success = Crypto::decryptFolder(filePath, password, outputPath, progressCallback);
            
            // Wenn das fehlschlägt, versuche es als normale Datei
            if (!success && Crypto::getLastError().find("keinen verschlüsselten Ordner") != std::string::npos) {
                success = Crypto::decryptFile(filePath, password, outputPath, progressCallback);
            }
        } else {
            // Verschlüssele eine normale Datei
            auto progressCallback = [](float progress) {
                updateProgress(progress, "Verschlüssele Datei");
            };
            
            success = Crypto::encryptFile(filePath, outputPath, password, level, progressCallback);
        }
    } catch (const std::exception& e) {
        showMessage(std::string("Fehler: ") + e.what(), "Fehler");
        return false;
    }
    
    // Ergebnis anzeigen
    if (success) {
        std::string message;
        if (isEncrypted) {
            message = "Datei/Ordner erfolgreich entschlüsselt.";
        } else if (isDirectory) {
            message = "Ordner erfolgreich verschlüsselt mit Sicherheitsstufe " + 
                     std::to_string(static_cast<int>(level)) + ".";
        } else {
            message = "Datei erfolgreich verschlüsselt mit Sicherheitsstufe " + 
                      std::to_string(static_cast<int>(level)) + ".";
        }
        showMessage(message, "Erfolgreich");
        return true;
    } else {
        showMessage("Fehler: " + Crypto::getLastError(), "Fehler");
        return false;
    }
}

} // namespace platform
} // namespace encrypt

#endif // !_WIN32