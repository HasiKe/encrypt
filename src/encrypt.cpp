#include "encrypt.h"
#include <iostream>
#include <fstream>
#include <bitset>

std::vector<bool> convertPasswordToBits(const std::string& password) {
    std::vector<bool> passwordBits;
    for (char c : password) {
        std::bitset<8> bits(static_cast<unsigned char>(c));
        for (int i = 7; i >= 0; --i) {
            passwordBits.push_back(bits[i]);
        }
    }
    return passwordBits;
}


std::string encryptString(const std::string& input, const std::vector<bool>& passwordBits) {
    std::string encrypted;
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
        encrypted.push_back(static_cast<char>(outputByte));
    }
    return encrypted;
}


bool encryptFile(const std::string& inputFileName, const std::string& outputFileName, const std::string& password) {
    // Passwort in Bits konvertieren
    std::vector<bool> passwordBits = convertPasswordToBits(password);

    // Eingabedatei im binären Modus öffnen
    std::ifstream inputFile(inputFileName, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Fehler beim Öffnen der Eingabedatei.\n";
        return false;
    }

    // Ausgabedatei im binären Modus öffnen
    std::ofstream outputFile(outputFileName, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Fehler beim Erstellen der Ausgabedatei.\n";
        return false;
    }

    // Verschlüsselung: Beispielcode (Dateiname verschlüsseln, dann Dateiinhalt verschlüsseln)
    try {
        // Verschlüsselten Dateinamen in die Ausgabedatei schreiben
        std::string encryptedFileName = encryptString(inputFileName, passwordBits);
        outputFile.write(encryptedFileName.c_str(), encryptedFileName.size());
        outputFile.put('\n');

        // Dateiinhalt verschlüsseln und schreiben
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
    } catch (...) {
        std::cerr << "Ein Fehler ist beim Verschlüsseln aufgetreten.\n";
        return false;
    }

    inputFile.close();
    outputFile.close();

    // Erfolgreiche Verschlüsselung
    std::cout << "Die Datei wurde erfolgreich verschlüsselt und als '" << outputFileName << "' gespeichert.\n";
    return true;
}

