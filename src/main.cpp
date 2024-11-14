#include <iostream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <sstream>

// Definieren Sie die Ressourcen-IDs für das Windows-Build
#define IDC_PASSWORD_INPUT 101
#define IDD_PASSWORD_DIALOG 102

// Globales Passwort für den Dialog
std::string g_password;

// Dialogfenster-Callback-Funktion
INT_PTR CALLBACK PasswordDialogProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_INITDIALOG:
            return TRUE;

        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                char password[256];
                GetDlgItemTextA(hwndDlg, IDC_PASSWORD_INPUT, password, 256);
                g_password = password;
                EndDialog(hwndDlg, IDOK);
                return TRUE;
            } else if (LOWORD(wParam) == IDCANCEL) {
                EndDialog(hwndDlg, IDCANCEL);
                return TRUE;
            }
            break;
    }
    return FALSE;
}


// Funktion zum Öffnen des Passwortdialogs
std::string getPasswordFromDialog() {
    DialogBoxParamA(NULL, MAKEINTRESOURCE(IDD_PASSWORD_DIALOG), NULL, PasswordDialogProc, 0);
    return g_password;
}

#else
// Standard-Eingabe für Linux
std::string getPasswordFromDialog() {
    std::string password;
    std::cout << "Bitte geben Sie das Passwort ein: ";
    std::cin >> password;
    return password;
}
#endif

#include "encrypt.h"
#include "decrypt.h"

void showMessage(const std::string& message) {
#ifdef _WIN32
    MessageBoxA(nullptr, message.c_str(), "Encryption", MB_OK | MB_ICONINFORMATION);
#else
    std::cout << message << std::endl;
#endif
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        showMessage("Verwendung: Ziehen Sie eine Datei auf dieses Programm, um sie zu verschlüsseln oder zu entschlüsseln.");
        return 1;
    }

    std::string inputFile = argv[1];
    std::string password;

    // Passwort über Dialog abfragen
    if (argc >= 3) {
        password = argv[2];
    } else {
        password = getPasswordFromDialog();
    }

    std::string extension;
    std::string name;

    // Überprüfen, ob der Dateiname eine Erweiterung hat
    size_t pos = inputFile.find_last_of('.');
    if (pos != std::string::npos) {
        name = inputFile.substr(0, pos);
        extension = inputFile.substr(pos);
    } else {
        showMessage("Kein Punkt im Dateinamen gefunden!");
        return 1;
    }

    // Entscheidung basierend auf der Dateierweiterung
    if (extension == ".cryp") {
        if (!decryptFile(inputFile, password)) {
            showMessage("Fehler bei der Entschlüsselung der Datei.");
            return 1;
        } else {
            showMessage("Datei erfolgreich entschlüsselt.");
        }
    } else {
        std::string outputFile = name + ".cryp";
        if (!encryptFile(inputFile, outputFile, password)) {
            showMessage("Fehler bei der Verschlüsselung der Datei.");
            return 1;
        } else {
            showMessage("Datei erfolgreich verschlüsselt.");
        }
    }

    return 0;
}
