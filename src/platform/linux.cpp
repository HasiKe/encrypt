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

} // namespace platform
} // namespace encrypt

#endif // !_WIN32