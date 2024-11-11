#include "decrypt.h"
#include <iostream>
#include <fstream>
#include <bitset>


std::string decryptString(const std::string& input, const std::vector<bool>& passwordBits) {
    std::string decrypted;
    size_t passwordBitIndex = 0;

    for (char c : input) {
        unsigned char inputByte = static_cast<unsigned char>(c);
        unsigned char outputByte = 0;

        for (int bitIndex = 7; bitIndex >= 0; --bitIndex) {
            bool inputBit = (inputByte >> bitIndex) & 0x01;
            bool passwordBit = passwordBits[passwordBitIndex % passwordBits.size()];

            bool outputBit = inputBit ^ passwordBit;
            outputByte |= (outputBit << bitIndex);

            passwordBitIndex++;
        }
        decrypted.push_back(static_cast<char>(outputByte));
    }
    return decrypted;
}

bool decryptFile(const std::string& inputFileName, const std::string& password) {
    std::vector<bool> passwordBits = convertPasswordToBits(password); // Verwendet die Funktion aus encrypt.cpp


    std::ifstream inputFile(inputFileName, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Fehler beim Öffnen der verschlüsselten Datei.\n";
        return false;
    }

    // Den verschlüsselten Dateinamen lesen und entschlüsseln
    std::string encryptedFileName;
    char ch;
    while (inputFile.get(ch) && ch != '\n') {
        encryptedFileName += ch;
    }

    std::string outputFileName = decryptString(encryptedFileName, passwordBits);
    std::ofstream outputFile(outputFileName, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Fehler beim Erstellen der Ausgabedatei.\n";
        return false;
    }

    // Verarbeitung der Eingabedatei bitweise
    char byte;
    size_t passwordBitIndex = 0;
    while (inputFile.get(byte)) {
        unsigned char inputByte = static_cast<unsigned char>(byte);
        unsigned char outputByte = 0;

        for (int bitIndex = 7; bitIndex >= 0; --bitIndex) {
            bool inputBit = (inputByte >> bitIndex) & 0x01;
            bool passwordBit = passwordBits[passwordBitIndex % passwordBits.size()];

            bool outputBit = inputBit ^ passwordBit;
            outputByte |= (outputBit << bitIndex);

            passwordBitIndex++;
        }

        outputFile.put(static_cast<char>(outputByte));
    }

    inputFile.close();
    outputFile.close();

    std::cout << "Die Datei wurde erfolgreich entschlüsselt und als '" << outputFileName << "' gespeichert.\n";
    return true;
}


