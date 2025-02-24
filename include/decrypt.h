#ifndef DECRYPT_H
#define DECRYPT_H

#include <string>
#include <vector>

std::vector<bool> convertPasswordToBits(const std::string& password);  // Nur Deklaration
std::string decryptString(const std::string& input, const std::vector<bool>& passwordBits);
bool decryptFile(const std::string& inputFileName, const std::string& password);

#endif // DECRYPT_H
