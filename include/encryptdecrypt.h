#ifndef DECRYPTDECRYPT_H
#define DECRYPTDECRYPT_H

#include <string>
#include <vector>

std::string decryptString(const std::string& input, const std::vector<bool>& passwordBits);
bool decryptFile(const std::string& inputFileName, const std::string& password);

std::vector<bool> convertPasswordToBits(const std::string& password);  // Nur Deklaration
std::string encryptString(const std::string& input, const std::vector<bool>& passwordBits);
bool encryptFile(const std::string& inputFileName, const std::string& outputFileName, const std::string& password);

#endif // DECRYPT_H
