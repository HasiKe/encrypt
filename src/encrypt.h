#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <string>
#include <vector>

std::vector<bool> convertPasswordToBits(const std::string& password);  // Nur Deklaration
std::string encryptString(const std::string& input, const std::vector<bool>& passwordBits);
bool encryptFile(const std::string& inputFileName, const std::string& outputFileName, const std::string& password);

#endif // ENCRYPT_H
