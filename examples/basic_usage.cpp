/**
 * @file basic_usage.cpp
 * @brief Grundlegendes Beispiel für die Verwendung der Encrypt-Bibliothek
 * 
 * Kompilieren:
 *   g++ -std=c++17 basic_usage.cpp -I../include -L../build -lencrypt_core -lssl -lcrypto -o basic_usage
 * 
 * Alternativ mit CMake:
 *   add_executable(basic_usage basic_usage.cpp)
 *   target_link_libraries(basic_usage encrypt_core)
 */

#include <encrypt/crypto.h>
#include <encrypt/platform.h>
#include <iostream>
#include <string>

using namespace Encrypt;

int main(int argc, char* argv[]) {
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  🔐 Encrypt Library - Basic Usage Example                    ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    // Datei zum Verschlüsseln
    std::string inputFile = "testfile.txt";
    std::string password = "MeinSicheresPasswort123!";
    
    // Demo-Datei erstellen
    std::cout << "[1] Erstelle Test-Datei...\n";
    {
        std::ofstream f(inputFile);
        f << "Dies ist ein geheimer Text, der verschlüsselt werden soll.\n";
        f << "Er enthält wichtige Informationen!\n";
    }
    std::cout << "    ✓ Datei erstellt: " << inputFile << "\n\n";
    
    // Passwort-Stärke prüfen
    std::cout << "[2] Prüfe Passwort-Stärke...\n";
    PasswordAnalysis analysis = Crypto::checkPasswordStrength(password);
    std::cout << "    Stärke: " << analysis.score << "/100 - " << analysis.category << "\n";
    std::cout << "    Details:\n";
    for (const auto& detail : analysis.details) {
        std::cout << "      • " << detail << "\n";
    }
    std::cout << "\n";
    
    // Verschlüsseln mit Level 2 (empfohlen)
    std::cout << "[3] Verschlüssele Datei mit Level 2...\n";
    EncryptionResult encResult = Crypto::encryptFile(
        inputFile,
        password,
        SecurityLevel::LEVEL_2  // Empfohlene Sicherheitsstufe
    );
    
    if (encResult.success) {
        std::cout << "    ✓ Verschlüsselt: " << encResult.outputPath << "\n";
        std::cout << "    Dauer: " << encResult.duration << " ms\n\n";
    } else {
        std::cerr << "    ✗ Fehler: " << encResult.errorMessage << "\n";
        return 1;
    }
    
    // Original-Datei löschen (optional)
    std::remove(inputFile.c_str());
    std::cout << "[4] Original-Datei gelöscht\n\n";
    
    // Entschlüsseln
    std::cout << "[5] Entschlüssele Datei...\n";
    EncryptionResult decResult = Crypto::decryptFile(
        encResult.outputPath,
        password
    );
    
    if (decResult.success) {
        std::cout << "    ✓ Entschlüsselt: " << decResult.outputPath << "\n";
        std::cout << "    Dauer: " << decResult.duration << " ms\n\n";
    } else {
        std::cerr << "    ✗ Fehler: " << decResult.errorMessage << "\n";
        return 1;
    }
    
    // Inhalt anzeigen
    std::cout << "[6] Entschlüsselter Inhalt:\n";
    std::cout << "    ────────────────────────────────────────\n";
    std::ifstream f(decResult.outputPath);
    std::string line;
    while (std::getline(f, line)) {
        std::cout << "    " << line << "\n";
    }
    std::cout << "    ────────────────────────────────────────\n\n";
    
    // Aufräumen
    std::remove(encResult.outputPath.c_str());
    std::remove(decResult.outputPath.c_str());
    
    std::cout << "✅ Beispiel erfolgreich abgeschlossen!\n";
    
    return 0;
}
