#include "encrypt/crypto.h"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cassert>
#include <cstdio>

// Einfache Test-Funktion
bool runTest(const std::string& testName, std::function<bool()> test) {
    std::cout << "Ausführen: " << testName << "... ";
    bool result = test();
    std::cout << (result ? "ERFOLG" : "FEHLGESCHLAGEN") << std::endl;
    return result;
}

// Hilfsfunktion zum Erstellen einer Testdatei
void createTestFile(const std::string& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    file.write(content.c_str(), content.size());
}

// Hilfsfunktion zum Lesen einer Datei
std::string readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}

int main() {
    int failedTests = 0;
    
    // Test: Verschlüsselung und Entschlüsselung einer einfachen Datei
    failedTests += !runTest("Einfacher Verschlüsselungstest", []() {
        const std::string testFile = "test_data.txt";
        const std::string encryptedFile = "test_data.cryp";
        const std::string decryptedFile = "test_data_decrypted.txt";
        const std::string testContent = "Dies ist ein Test für die Verschlüsselung!\nZeile 2\nZeile 3";
        const std::string password = "TestPasswort123!";
        
        // Testdatei erstellen
        createTestFile(testFile, testContent);
        
        // Datei verschlüsseln
        bool encryptResult = encrypt::Crypto::encryptFile(testFile, encryptedFile, password);
        if (!encryptResult) {
            std::cerr << "Verschlüsselungsfehler: " << encrypt::Crypto::getLastError() << std::endl;
            return false;
        }
        
        // Verschlüsselte Datei entschlüsseln
        bool decryptResult = encrypt::Crypto::decryptFile(encryptedFile, password, decryptedFile);
        if (!decryptResult) {
            std::cerr << "Entschlüsselungsfehler: " << encrypt::Crypto::getLastError() << std::endl;
            return false;
        }
        
        // Prüfen, ob die entschlüsselte Datei den ursprünglichen Inhalt hat
        std::string decryptedContent = readFile(decryptedFile);
        bool contentMatches = (decryptedContent == testContent);
        
        // Aufräumen
        std::remove(testFile.c_str());
        std::remove(encryptedFile.c_str());
        std::remove(decryptedFile.c_str());
        
        return contentMatches;
    });
    
    // Test: Falsches Passwort sollte zu Fehlern führen
    failedTests += !runTest("Falsches Passwort Test", []() {
        const std::string testFile = "wrong_password_test.txt";
        const std::string encryptedFile = "wrong_password_test.cryp";
        const std::string decryptedFile = "wrong_password_decrypted.txt";
        const std::string testContent = "Dies ist ein Test für falsches Passwort!";
        
        // Testdatei erstellen
        createTestFile(testFile, testContent);
        
        // Datei verschlüsseln mit Passwort1
        bool encryptResult = encrypt::Crypto::encryptFile(testFile, encryptedFile, "Passwort1");
        if (!encryptResult) {
            return false;
        }
        
        // Datei mit falschem Passwort entschlüsseln versuchen
        bool decryptResult = encrypt::Crypto::decryptFile(encryptedFile, "FalschesPasswort", decryptedFile);
        
        // Die entschlüsselte Datei sollte entweder nicht existieren oder unterschiedlichen Inhalt haben
        bool contentDiffers = true;
        if (decryptResult) {
            std::string decryptedContent = readFile(decryptedFile);
            contentDiffers = (decryptedContent != testContent);
        }
        
        // Aufräumen
        std::remove(testFile.c_str());
        std::remove(encryptedFile.c_str());
        std::remove(decryptedFile.c_str());
        
        // Der Test ist erfolgreich, wenn die Entschlüsselung fehlschlägt oder der Inhalt unterschiedlich ist
        return !decryptResult || contentDiffers;
    });
    
    // Ergebnis ausgeben
    if (failedTests == 0) {
        std::cout << "\nAlle Tests erfolgreich abgeschlossen!" << std::endl;
        return 0;
    } else {
        std::cout << "\n" << failedTests << " Tests fehlgeschlagen!" << std::endl;
        return 1;
    }
}