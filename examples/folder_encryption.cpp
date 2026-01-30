/**
 * @file folder_encryption.cpp
 * @brief Beispiel für Ordner-Verschlüsselung und Sicherheitsstufen
 * 
 * Kompilieren:
 *   g++ -std=c++17 folder_encryption.cpp -I../include -L../build -lencrypt_core -lssl -lcrypto -o folder_encryption
 */

#include <encrypt/crypto.h>
#include <encrypt/platform.h>
#include <iostream>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;
using namespace Encrypt;

/**
 * @brief Zeigt Informationen zu allen Sicherheitsstufen
 */
void showSecurityLevels() {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  📊 Verfügbare Sicherheitsstufen                             ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    
    const char* levels[] = {
        "Level 1 │ Standard     │ AES-128-GCM │  10K Iter │ Schnell",
        "Level 2 │ Empfohlen    │ AES-256-GCM │ 100K Iter │ Ausgewogen",
        "Level 3 │ Hoch         │ AES-256-GCM │ 250K Iter │ Sicher",
        "Level 4 │ Militär      │ AES-256-GCM │ 500K Iter │ Sehr sicher",
        "Level 5 │ Paranoid     │ Dual-Cipher │   1M Iter │ Maximum"
    };
    
    for (int i = 0; i < 5; i++) {
        std::cout << "║  " << levels[i];
        // Padding
        size_t len = strlen(levels[i]);
        for (size_t j = len; j < 58; j++) std::cout << " ";
        std::cout << "║\n";
    }
    
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
}

/**
 * @brief Erstellt einen Test-Ordner mit Dateien
 */
void createTestFolder(const std::string& path) {
    fs::create_directories(path);
    fs::create_directories(path + "/documents");
    fs::create_directories(path + "/images");
    
    // Dokumente
    {
        std::ofstream f(path + "/readme.txt");
        f << "Dies ist ein geheimer Ordner.\n";
        f << "Alle Dateien werden verschlüsselt.\n";
    }
    
    {
        std::ofstream f(path + "/documents/bericht.txt");
        f << "Geheimer Bericht Q4 2025\n";
        f << "========================\n";
        f << "Umsatz: 1.2M EUR\n";
        f << "Gewinn: 300K EUR\n";
    }
    
    {
        std::ofstream f(path + "/documents/notizen.txt");
        f << "Wichtige Notizen:\n";
        f << "- Meeting am Montag\n";
        f << "- Deadline Freitag\n";
    }
    
    // Simulierte "Bilder" (Text-Dateien als Platzhalter)
    {
        std::ofstream f(path + "/images/foto1.data");
        f << std::string(1024, 'X');  // 1KB Dummy-Daten
    }
    
    {
        std::ofstream f(path + "/images/foto2.data");
        f << std::string(2048, 'Y');  // 2KB Dummy-Daten
    }
}

/**
 * @brief Zeigt Ordnerstruktur rekursiv an
 */
void showFolderStructure(const std::string& path, int indent = 0) {
    for (const auto& entry : fs::directory_iterator(path)) {
        for (int i = 0; i < indent; i++) std::cout << "  ";
        
        if (entry.is_directory()) {
            std::cout << "📁 " << entry.path().filename().string() << "/\n";
            showFolderStructure(entry.path().string(), indent + 1);
        } else {
            auto size = fs::file_size(entry);
            std::cout << "📄 " << entry.path().filename().string() 
                      << " (" << size << " bytes)\n";
        }
    }
}

int main() {
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  🔐 Encrypt Library - Folder Encryption Example              ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    
    // Sicherheitsstufen anzeigen
    showSecurityLevels();
    
    const std::string testFolder = "test_geheim";
    const std::string password = "Ordner$Sicher_2025!";
    
    // Test-Ordner erstellen
    std::cout << "[1] Erstelle Test-Ordner...\n\n";
    createTestFolder(testFolder);
    
    std::cout << "    Ordnerstruktur:\n";
    std::cout << "    " << testFolder << "/\n";
    showFolderStructure(testFolder, 2);
    std::cout << "\n";
    
    // Passwort-Analyse
    std::cout << "[2] Passwort-Analyse:\n";
    auto analysis = Crypto::checkPasswordStrength(password);
    std::cout << "    Score: " << analysis.score << "/100 (" << analysis.category << ")\n\n";
    
    // Ordner verschlüsseln mit Level 3
    std::cout << "[3] Verschlüssele Ordner mit Level 3 (Hoch)...\n";
    auto encResult = Crypto::encryptFolder(testFolder, password, SecurityLevel::LEVEL_3);
    
    if (encResult.success) {
        std::cout << "    ✓ Archiv erstellt: " << encResult.outputPath << "\n";
        std::cout << "    Dauer: " << encResult.duration << " ms\n";
        std::cout << "    Größe: " << fs::file_size(encResult.outputPath) << " bytes\n\n";
    } else {
        std::cerr << "    ✗ Fehler: " << encResult.errorMessage << "\n";
        return 1;
    }
    
    // Original-Ordner löschen
    std::cout << "[4] Lösche Original-Ordner...\n";
    fs::remove_all(testFolder);
    std::cout << "    ✓ Ordner gelöscht\n\n";
    
    // Prüfen ob verschlüsselte Datei erkannt wird
    std::cout << "[5] Prüfe verschlüsselte Datei...\n";
    if (Crypto::isEncryptedFile(encResult.outputPath)) {
        std::cout << "    ✓ Datei ist verschlüsselt\n";
        
        // Header-Informationen lesen
        auto header = Crypto::parseFileHeader(encResult.outputPath);
        std::cout << "    Version: " << static_cast<int>(header.version) << "\n";
        std::cout << "    Level: " << static_cast<int>(header.securityLevel) << "\n";
        std::cout << "    Ist Ordner: " << (header.isFolder ? "Ja" : "Nein") << "\n\n";
    }
    
    // Ordner entschlüsseln
    std::cout << "[6] Entschlüssele Archiv...\n";
    auto decResult = Crypto::decryptFolder(encResult.outputPath, password);
    
    if (decResult.success) {
        std::cout << "    ✓ Ordner wiederhergestellt: " << decResult.outputPath << "\n";
        std::cout << "    Dauer: " << decResult.duration << " ms\n\n";
        
        std::cout << "    Wiederhergestellte Struktur:\n";
        std::cout << "    " << decResult.outputPath << "/\n";
        showFolderStructure(decResult.outputPath, 2);
    } else {
        std::cerr << "    ✗ Fehler: " << decResult.errorMessage << "\n";
        return 1;
    }
    
    // Aufräumen
    std::cout << "\n[7] Aufräumen...\n";
    fs::remove(encResult.outputPath);
    fs::remove_all(decResult.outputPath);
    std::cout << "    ✓ Temporäre Dateien gelöscht\n";
    
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  ✅ Beispiel erfolgreich abgeschlossen!                      ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return 0;
}
