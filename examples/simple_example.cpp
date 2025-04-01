#include "encrypt/crypto.h"
#include "encrypt/platform.h"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Verwendung: simple_example <Datei>" << std::endl;
        return 1;
    }
    
    std::string inputFile = argv[1];
    
    // Passwort vom Benutzer abfragen
    std::string password = encrypt::platform::getPassword();
    if (password.empty()) {
        std::cout << "Kein Passwort eingegeben. Vorgang abgebrochen." << std::endl;
        return 1;
    }
    
    // Prüfen ob es sich um eine verschlüsselte Datei handelt
    bool isEncrypted = false;
    size_t pos = inputFile.find_last_of('.');
    if (pos != std::string::npos) {
        std::string extension = inputFile.substr(pos);
        isEncrypted = (extension == ".cryp");
    }
    
    // Fortschrittsanzeige-Callback
    auto progressCallback = [](float progress) {
        encrypt::platform::updateProgress(progress, "Verarbeite Datei");
    };
    
    // Ver- oder Entschlüsselung durchführen
    bool success = false;
    if (isEncrypted) {
        std::cout << "Entschlüssele Datei..." << std::endl;
        success = encrypt::Crypto::decryptFile(inputFile, password, "", progressCallback);
    } else {
        std::string outputFile = inputFile + ".cryp";
        std::cout << "Verschlüssele Datei..." << std::endl;
        success = encrypt::Crypto::encryptFile(inputFile, outputFile, password, progressCallback);
    }
    
    // Ergebnis anzeigen
    if (success) {
        std::cout << "Vorgang erfolgreich abgeschlossen." << std::endl;
    } else {
        std::cerr << "Fehler: " << encrypt::Crypto::getLastError() << std::endl;
        return 1;
    }
    
    return 0;
}