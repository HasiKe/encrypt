#include "encrypt/platform.h"

#ifdef _WIN32

#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <iostream>
#include <string>
#include <filesystem>

namespace encrypt {
namespace platform {

// ID für den Dialog
constexpr int IDD_PASSWORD_DIALOG = 102;
constexpr int IDC_PASSWORD_INPUT = 101;
constexpr int IDC_PROGRESS_BAR = 103;

// Globale Variablen für den Dialog
std::string g_password;
HWND g_progressBar = nullptr;

// Dialogfenster-Callback-Funktion für Passwortabfrage
INT_PTR CALLBACK PasswordDialogProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_INITDIALOG:
            // Dialog initialisieren und Eingabefeld fokussieren
            SetFocus(GetDlgItem(hwndDlg, IDC_PASSWORD_INPUT));
            return TRUE;

        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                // OK-Button wurde geklickt
                char password[256] = {0};
                GetDlgItemTextA(hwndDlg, IDC_PASSWORD_INPUT, password, sizeof(password));
                g_password = password;
                EndDialog(hwndDlg, IDOK);
                return TRUE;
            } else if (LOWORD(wParam) == IDCANCEL) {
                // Abbrechen-Button wurde geklickt
                EndDialog(hwndDlg, IDCANCEL);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

void showMessage(const std::string& message, const std::string& title) {
    MessageBoxA(nullptr, message.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
}

std::string getPassword(const std::string& prompt) {
    // Ressourcen-basierter Dialog
    int result = DialogBoxParamA(
        GetModuleHandle(NULL), 
        MAKEINTRESOURCE(IDD_PASSWORD_DIALOG), 
        NULL, 
        PasswordDialogProc, 
        0
    );

    if (result != IDOK) {
        // Benutzer hat abgebrochen
        return "";
    }
    
    return g_password;
}

void updateProgress(float progress, const std::string& operation) {
    if (g_progressBar == NULL) {
        // Einfaches Fenster für Fortschrittsanzeige erstellen, falls noch nicht vorhanden
        HWND hwnd = CreateWindowExA(
            0, "STATIC", "Fortschritt", 
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE,
            CW_USEDEFAULT, CW_USEDEFAULT, 300, 100, NULL, NULL, GetModuleHandle(NULL), NULL
        );
        
        // Fortschrittsbalken erstellen
        g_progressBar = CreateWindowExA(
            0, PROGRESS_CLASS, NULL, 
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
            10, 40, 280, 20, hwnd, NULL, GetModuleHandle(NULL), NULL
        );
        
        // Beschriftung erstellen
        CreateWindowExA(
            0, "STATIC", operation.c_str(),
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            10, 10, 280, 20, hwnd, NULL, GetModuleHandle(NULL), NULL
        );
        
        // Fortschrittsbalken-Bereich setzen
        SendMessage(g_progressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    }
    
    // Fortschrittsbalken aktualisieren
    int pos = static_cast<int>(progress * 100);
    SendMessage(g_progressBar, PBM_SETPOS, pos, 0);
    
    // Windows-Ereignisse verarbeiten
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

std::string normalizePath(const std::string& path) {
    std::string result = path;
    
    // Ersetze "/" durch "\"
    for (char& c : result) {
        if (c == '/') {
            c = '\\';
        }
    }
    
    return result;
}

std::string getFileName(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    if (pos != std::string::npos) {
        return path.substr(pos + 1);
    }
    return path;
}

bool fileExists(const std::string& path) {
    DWORD attributes = GetFileAttributesA(path.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES && 
            !(attributes & FILE_ATTRIBUTE_DIRECTORY));
}

} // namespace platform
} // namespace encrypt

#endif // _WIN32