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
 * @brief Zeigt die Programmhilfe an
 */
void printHelp() {
    std::cout << "Verwendung: encrypt [Optionen] <Datei>" << std::endl;
    std::cout << std::endl;
    std::cout << "Optionen:" << std::endl;
    std::cout << "  -h, --help              Diese Hilfe anzeigen" << std::endl;
    std::cout << "  -d, --decrypt           Datei entschlüsseln (Standard: verschlüsseln)" << std::endl;
    std::cout << "  -o, --output <Datei>    Ausgabedatei angeben" << std::endl;
    std::cout << "  -p, --password <Pass>   Passwort angeben (UNSICHER, besser interaktiv!)" << std::endl;
    std::cout << "  -l, --level <1-5>       Sicherheitsstufe angeben (1=schnell, 5=max. sicher)" << std::endl;
    std::cout << "  -c, --check-password    Passwort-Stärke prüfen ohne Verschlüsselung" << std::endl;
    std::cout << std::endl;
    std::cout << "Sicherheitsstufen:" << std::endl;
    std::cout << "  1: Schnell, gut für unkritische Daten (AES-128-GCM, PBKDF2 mit 10.000 Iterationen)" << std::endl;
    std::cout << "  2: Ausgewogen, Standard (AES-256-GCM, PBKDF2 mit 100.000 Iterationen)" << std::endl;
    std::cout << "  3: Erhöhte Sicherheit (AES-256-GCM, PBKDF2 mit 250.000 Iterationen)" << std::endl;
    std::cout << "  4: Hohe Sicherheit (AES-256-GCM, Argon2id mit 64MB RAM)" << std::endl;
    std::cout << "  5: Maximale Sicherheit (AES-256-GCM + ChaCha20, Argon2id mit 256MB RAM)" << std::endl;
    std::cout << std::endl;
    std::cout << "Beispiele:" << std::endl;
    std::cout << "  encrypt MeineDokument.docx             # Verschlüsselt die Datei mit Standard-Sicherheit" << std::endl;
    std::cout << "  encrypt -l 4 MeineDokument.docx        # Verschlüsselt mit hoher Sicherheit" << std::endl;
    std::cout << "  encrypt -d MeineDokument.docx.cryp     # Entschlüsselt die Datei" << std::endl;
    std::cout << "  encrypt -c                             # Interaktiver Passwort-Check" << std::endl;
}

/**
 * @brief Zeigt die Passwort-Stärkebewertung an
 */
void displayPasswordStrength(const std::string& password) {
    int strength = Crypto::checkPasswordStrength(password);
    
    // Bestimme die Kategorie
    std::string category;
    if (strength < 20) category = "Sehr schwach";
    else if (strength < 40) category = "Schwach";
    else if (strength < 60) category = "Mittel";
    else if (strength < 80) category = "Stark";
    else category = "Sehr stark";
    
    // Bestimme die Farbe (ANSI-Escape-Sequenzen)
    std::string colorStart, colorEnd = "\033[0m";
    if (strength < 20) colorStart = "\033[1;31m"; // Rot, fett
    else if (strength < 40) colorStart = "\033[0;31m"; // Rot
    else if (strength < 60) colorStart = "\033[0;33m"; // Gelb
    else if (strength < 80) colorStart = "\033[0;32m"; // Grün
    else colorStart = "\033[1;32m"; // Grün, fett
    
    // Fortschrittsbalken erstellen
    const int barWidth = 30;
    int filledWidth = barWidth * strength / 100;
    
    std::cout << "Passwort-Stärke: " << colorStart << strength << "/100 (" << category << ")" << colorEnd << std::endl;
    
    // Balkendarstellung
    std::cout << "[";
    for (int i = 0; i < barWidth; ++i) {
        if (i < filledWidth) {
            std::cout << colorStart << "=" << colorEnd;
        } else {
            std::cout << " ";
        }
    }
    std::cout << "]" << std::endl;
    
    // Empfehlungen
    if (strength < 60) {
        std::cout << "\nEmpfehlungen zur Verbesserung:" << std::endl;
        if (password.length() < 12) {
            std::cout << "- Verwenden Sie ein längeres Passwort (mind. 12 Zeichen)" << std::endl;
        }
        
        bool hasLower = std::any_of(password.begin(), password.end(), [](char c) { return islower(c); });
        bool hasUpper = std::any_of(password.begin(), password.end(), [](char c) { return isupper(c); });
        bool hasDigit = std::any_of(password.begin(), password.end(), [](char c) { return isdigit(c); });
        bool hasSpecial = std::any_of(password.begin(), password.end(), [](char c) { return !isalnum(c); });
        
        if (!hasLower) std::cout << "- Fügen Sie Kleinbuchstaben hinzu" << std::endl;
        if (!hasUpper) std::cout << "- Fügen Sie Großbuchstaben hinzu" << std::endl;
        if (!hasDigit) std::cout << "- Fügen Sie Zahlen hinzu" << std::endl;
        if (!hasSpecial) std::cout << "- Fügen Sie Sonderzeichen hinzu" << std::endl;
    }
}

/**
 * @brief Interaktiver Passwort-Check
 */
void interactivePasswordCheck() {
    std::cout << "=== Passwort-Stärke-Prüfung ===" << std::endl;
    std::cout << "Geben Sie ein Passwort ein (oder eine leere Zeile zum Beenden):" << std::endl;
    
    while (true) {
        std::string password = platform::getPassword("Passwort: ");
        if (password.empty()) {
            break;
        }
        
        displayPasswordStrength(password);
        std::cout << "\nNeues Passwort eingeben (oder leer zum Beenden):" << std::endl;
    }
}

/**
 * @brief Hauptfunktion für CLI
 * 
 * @param argc Anzahl der Argumente
 * @param argv Argumentwerte
 * @return int Programmrückgabewert
 */
int run(int argc, char* argv[]) {
    if (argc < 2) {
        printHelp();
        return 1;
    }
    
    // Standardwerte
    bool decrypt = false;
    bool checkPasswordMode = false;
    std::string inputFile;
    std::string outputFile;
    std::string password;
    SecurityLevel level = SecurityLevel::LEVEL_2; // Standardlevel
    
    // Argumente verarbeiten
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
                platform::showMessage("Ungültige Sicherheitsstufe. Bitte einen Wert zwischen 1 und 5 angeben.", "Fehler");
                return 1;
            }
            level = static_cast<SecurityLevel>(levelValue);
        } else if (arg[0] == '-') {
            platform::showMessage("Unbekannte Option: " + arg, "Fehler");
            return 1;
        } else {
            // Dateiname (ohne Option)
            inputFile = arg;
        }
    }
    
    // Modus für Passwort-Prüfung
    if (checkPasswordMode) {
        interactivePasswordCheck();
        return 0;
    }
    
    // Prüfen, ob Eingabedatei angegeben wurde (außer im Passwort-Check-Modus)
    if (inputFile.empty()) {
        platform::showMessage("Keine Eingabedatei angegeben!", "Fehler");
        return 1;
    }
    
    // Prüfen, ob Datei existiert
    if (!platform::fileExists(inputFile)) {
        platform::showMessage("Datei existiert nicht: " + inputFile, "Fehler");
        return 1;
    }
    
    // Standardausgabedatei bestimmen, falls nicht angegeben
    if (outputFile.empty()) {
        if (decrypt) {
            // Bei Entschlüsselung wird der Name aus der Datei gelesen
            // Ausgabedateiname wird später bestimmt
        } else {
            outputFile = inputFile + ".cryp";
        }
    }
    
    // Passwort interaktiv abfragen, falls nicht angegeben
    if (password.empty()) {
        password = platform::getPassword();
        
        // Zweite Eingabe zur Bestätigung bei Verschlüsselung
        if (!decrypt) {
            std::string confirmPassword = platform::getPassword("Passwort wiederholen: ");
            if (password != confirmPassword) {
                platform::showMessage("Passwörter stimmen nicht überein!", "Fehler");
                return 1;
            }
        }
        
        if (password.empty()) {
            platform::showMessage("Kein Passwort angegeben. Vorgang abgebrochen.", "Abbruch");
            return 1;
        }
    }
    
    // Bei Verschlüsselung Passwort-Stärke prüfen
    if (!decrypt) {
        int passwordStrength = Crypto::checkPasswordStrength(password);
        
        if (passwordStrength < 40) {
            std::string message = "Warnung: Schwaches Passwort (Stärke: " + 
                                std::to_string(passwordStrength) + "/100)\n" +
                                "Möchten Sie trotzdem fortfahren? (j/n): ";
                                
            std::cout << message;
            char response;
            std::cin >> response;
            
            if (response != 'j' && response != 'J') {
                platform::showMessage("Vorgang abgebrochen.", "Abbruch");
                return 1;
            }
        }
    }
    
    // Fortschrittsanzeige-Callback
    auto progressCallback = [decrypt](float progress) {
        platform::updateProgress(progress, decrypt ? "Entschlüssele Datei" : "Verschlüssele Datei");
    };
    
    // Ver- oder Entschlüsselung durchführen
    bool success = false;
    
    try {
        // Nachdem der Encryption-Test erfolgreich war, können wir jetzt auch die Datei-Verschlüsselung nutzen
        std::cerr << "Starte Datei-Verschlüsselung" << std::endl;
        
        if (decrypt) {
            success = Crypto::decryptFile(inputFile, password, outputFile, progressCallback);
        } else {
            success = Crypto::encryptFile(inputFile, outputFile, password, level, progressCallback);
        }
    } catch (const std::exception& e) {
        std::cerr << "EXCEPTION: " << e.what() << std::endl;
        platform::showMessage(std::string("Ausnahmefehler: ") + e.what(), "Fehler");
        return 1;
    } catch (...) {
        std::cerr << "UNKNOWN EXCEPTION" << std::endl;
        platform::showMessage("Unbekannter Ausnahmefehler", "Fehler");
        return 1;
    }
    
    // Ergebnis anzeigen
    if (success) {
        std::string message = decrypt 
            ? "Datei erfolgreich entschlüsselt."
            : "Datei erfolgreich verschlüsselt mit Sicherheitsstufe " + std::to_string(static_cast<int>(level)) + ".";
        platform::showMessage(message, "Erfolgreich");
        return 0;
    } else {
        platform::showMessage("Fehler: " + Crypto::getLastError(), "Fehler");
        return 1;
    }
}

} // namespace ui
} // namespace encrypt