#include "encrypt/platform.h"
#include "encrypt/crypto.h"

#ifdef _WIN32

// Füge UI-Funktionalität hinzu
namespace encrypt {
namespace ui {
    int run(int argc, char* argv[]);
}
}

#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <vector>

namespace encrypt {
namespace platform {

// IDs für Dialoge und Steuerelemente
constexpr int IDD_PASSWORD_DIALOG = 102;
constexpr int IDC_PASSWORD_INPUT = 101;
constexpr int IDC_PASSWORD_CONFIRM = 102;
constexpr int IDC_PROGRESS_BAR = 103;

// IDs für Security Level Dialog
constexpr int IDD_SECURITY_DIALOG = 201;
constexpr int IDC_RADIO_LEVEL1 = 202;
constexpr int IDC_RADIO_LEVEL2 = 203;
constexpr int IDC_RADIO_LEVEL3 = 204;
constexpr int IDC_RADIO_LEVEL4 = 205;
constexpr int IDC_RADIO_LEVEL5 = 206;

// Globale Variablen für die Dialoge
std::string g_password;
HWND g_progressBar = nullptr;
SecurityLevel g_securityLevel = SecurityLevel::LEVEL_2;
bool g_confirmPassword = false;

// Dialogfenster-Callback-Funktion für Sicherheitsstufe
INT_PTR CALLBACK SecurityLevelDialogProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM /*lParam*/) {
    switch (message) {
        case WM_INITDIALOG: {
            // Standard-Radio-Button auswählen (Level 2)
            CheckRadioButton(hwndDlg, IDC_RADIO_LEVEL1, IDC_RADIO_LEVEL5, IDC_RADIO_LEVEL2);
            return TRUE;
        }

        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                // Bestimmen, welcher Radio-Button ausgewählt wurde
                if (IsDlgButtonChecked(hwndDlg, IDC_RADIO_LEVEL1))
                    g_securityLevel = SecurityLevel::LEVEL_1;
                else if (IsDlgButtonChecked(hwndDlg, IDC_RADIO_LEVEL2))
                    g_securityLevel = SecurityLevel::LEVEL_2;
                else if (IsDlgButtonChecked(hwndDlg, IDC_RADIO_LEVEL3))
                    g_securityLevel = SecurityLevel::LEVEL_3;
                else if (IsDlgButtonChecked(hwndDlg, IDC_RADIO_LEVEL4))
                    g_securityLevel = SecurityLevel::LEVEL_4;
                else if (IsDlgButtonChecked(hwndDlg, IDC_RADIO_LEVEL5))
                    g_securityLevel = SecurityLevel::LEVEL_5;
                
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

// Dialogfenster-Callback-Funktion für Passwortabfrage
INT_PTR CALLBACK PasswordDialogProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM /*lParam*/) {
    switch (message) {
        case WM_INITDIALOG:
            // Dialog initialisieren und Eingabefeld fokussieren
            SetFocus(GetDlgItem(hwndDlg, IDC_PASSWORD_INPUT));
            
            // Wenn Passwortbestätigung benötigt wird, zeige das zweite Feld an
            if (g_confirmPassword) {
                // Hier könnten wir das Bestätigungsfeld anzeigen, falls wir es im Dialog definiert haben
                ShowWindow(GetDlgItem(hwndDlg, IDC_PASSWORD_CONFIRM), SW_SHOW);
            } else {
                // Verstecke das Bestätigungsfeld, wenn nicht benötigt
                ShowWindow(GetDlgItem(hwndDlg, IDC_PASSWORD_CONFIRM), SW_HIDE);
            }
            
            return TRUE;

        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                // OK-Button wurde geklickt
                char password[256] = {0};
                GetDlgItemTextA(hwndDlg, IDC_PASSWORD_INPUT, password, sizeof(password));
                g_password = password;
                
                // Wenn Passwortbestätigung benötigt wird
                if (g_confirmPassword) {
                    char confirmPassword[256] = {0};
                    GetDlgItemTextA(hwndDlg, IDC_PASSWORD_CONFIRM, confirmPassword, sizeof(confirmPassword));
                    
                    // Prüfen, ob Passwörter übereinstimmen
                    if (g_password != confirmPassword) {
                        MessageBoxA(hwndDlg, "Die Passwörter stimmen nicht überein!", "Fehler", MB_OK | MB_ICONERROR);
                        return TRUE; // Dialog offen halten
                    }
                }
                
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

std::string getPassword(const std::string& /*prompt*/) {
    // Ressourcen-basierter Dialog
    g_confirmPassword = false; // Standardmäßig keine Bestätigung
    
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

std::string getPasswordWithConfirmation() {
    // Ressourcen-basierter Dialog mit Bestätigung
    g_confirmPassword = true;
    
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

SecurityLevel getSecurityLevel() {
    // Dialog zur Auswahl der Sicherheitsstufe anzeigen
    int result = DialogBoxParamA(
        GetModuleHandle(NULL), 
        MAKEINTRESOURCE(IDD_SECURITY_DIALOG), 
        NULL, 
        SecurityLevelDialogProc, 
        0
    );

    if (result != IDOK) {
        // Benutzer hat abgebrochen, verwende Standardlevel
        return SecurityLevel::LEVEL_2;
    }
    
    return g_securityLevel;
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

// Funktion zum Bestimmen, ob eine Datei verschlüsselt ist (basierend auf der Dateierweiterung)
bool isEncryptedFile(const std::string& path) {
    size_t pos = path.find_last_of('.');
    if (pos != std::string::npos) {
        std::string extension = path.substr(pos);
        return (extension == ".cryp");
    }
    return false;
}

// Funktion zum Prüfen, ob ein Pfad ein Ordner ist
bool isFolder(const std::string& path) {
    DWORD attributes = GetFileAttributesA(path.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES && 
            (attributes & FILE_ATTRIBUTE_DIRECTORY));
}

// Hilfsfunktion zum Verarbeiten einer Datei oder eines Ordners (Ver- oder Entschlüsselung)
bool processFile(const std::string& filePath) {
    bool isEncrypted = isEncryptedFile(filePath);
    bool isDirectory = isFolder(filePath);
    
    // Bestimme den Ausgabepfad
    std::string outputPath;
    if (isEncrypted) {
        // Bei verschlüsselten Dateien wird der Name beim Entschlüsseln automatisch bestimmt
        outputPath = "";
    } else {
        // Bei unverschlüsselten Dateien/Ordnern fügen wir .cryp hinzu
        outputPath = filePath + ".cryp";
    }
    
    // Hole das Passwort
    std::string password;
    if (isEncrypted) {
        // Für Entschlüsselung benötigen wir keine Passwortbestätigung
        password = getPassword();
    } else {
        // Für Verschlüsselung benötigen wir eine Passwortbestätigung
        password = getPasswordWithConfirmation();
    }
    
    if (password.empty()) {
        showMessage("Kein Passwort angegeben. Vorgang abgebrochen.", "Abbruch");
        return false;
    }
    
    // Bei Verschlüsselung: Frage nach Sicherheitsstufe
    SecurityLevel level = SecurityLevel::LEVEL_2;
    if (!isEncrypted) {
        level = getSecurityLevel();
    }
    
    // Ver- oder Entschlüsselung durchführen
    bool success = false;
    try {
        // Unterschiedliche Behandlung für Dateien und Ordner
        if (isDirectory && !isEncrypted) {
            // Verschlüssele einen Ordner
            auto progressCallback = [](float progress) {
                updateProgress(progress, "Verschlüssele Ordner");
            };
            
            success = Crypto::encryptFolder(filePath, outputPath, password, level, progressCallback);
        } else if (isEncrypted) {
            // Entschlüssele eine Datei (könnte ein verschlüsselter Ordner sein)
            auto progressCallback = [](float progress) {
                updateProgress(progress, "Entschlüssele Datei/Ordner");
            };
            
            // Versuche zuerst als Ordner zu entschlüsseln
            success = Crypto::decryptFolder(filePath, password, outputPath, progressCallback);
            
            // Wenn das fehlschlägt, versuche es als normale Datei
            if (!success && Crypto::getLastError().find("keinen verschlüsselten Ordner") != std::string::npos) {
                success = Crypto::decryptFile(filePath, password, outputPath, progressCallback);
            }
        } else {
            // Verschlüssele eine normale Datei
            auto progressCallback = [](float progress) {
                updateProgress(progress, "Verschlüssele Datei");
            };
            
            success = Crypto::encryptFile(filePath, outputPath, password, level, progressCallback);
        }
    } catch (const std::exception& e) {
        showMessage(std::string("Fehler: ") + e.what(), "Fehler");
        return false;
    }
    
    // Ergebnis anzeigen
    if (success) {
        std::string message;
        if (isEncrypted) {
            message = "Datei/Ordner erfolgreich entschlüsselt.";
        } else if (isDirectory) {
            message = "Ordner erfolgreich verschlüsselt mit Sicherheitsstufe " + 
                     std::to_string(static_cast<int>(level)) + ".";
        } else {
            message = "Datei erfolgreich verschlüsselt mit Sicherheitsstufe " + 
                      std::to_string(static_cast<int>(level)) + ".";
        }
        showMessage(message, "Erfolgreich");
        return true;
    } else {
        showMessage("Fehler: " + Crypto::getLastError(), "Fehler");
        return false;
    }
}

} // namespace platform
} // namespace encrypt

// Hauptfenster-Prozedur für das Drag-and-Drop-Fenster
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            // Aktiviere Drag-and-Drop für dieses Fenster
            DragAcceptFiles(hwnd, TRUE);
            return 0;
            
        case WM_DROPFILES: {
            HDROP hDrop = (HDROP)wParam;
            UINT fileCount = DragQueryFileA(hDrop, 0xFFFFFFFF, NULL, 0);
            
            // Verarbeite alle gezogenen Dateien
            for (UINT i = 0; i < fileCount; i++) {
                char filePath[MAX_PATH];
                DragQueryFileA(hDrop, i, filePath, MAX_PATH);
                
                // Versuche die Datei zu ver- oder entschlüsseln
                encrypt::platform::processFile(filePath);
            }
            
            DragFinish(hDrop);
            return 0;
        }
            
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Zeichne einen einfachen Hinweistext
            RECT rect;
            GetClientRect(hwnd, &rect);
            
            const char* instructions = "Ziehen Sie Dateien hierher, um sie zu ver- oder entschlüsseln.\n\n"
                                      "Dateien mit der Endung .cryp werden entschlüsselt,\n"
                                      "alle anderen Dateien werden verschlüsselt.";
            
            SetTextColor(hdc, RGB(0, 0, 0));
            SetBkMode(hdc, TRANSPARENT);
            DrawTextA(hdc, instructions, -1, &rect, DT_CENTER | DT_VCENTER);
            
            EndPaint(hwnd, &ps);
            return 0;
        }
            
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Windows-Haupteinstiegspunkt für das Drag-and-Drop-Fenster
extern "C" int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPSTR /*lpCmdLine*/, int nCmdShow) {
    // Prüfe, ob Kommandozeilenargumente vorhanden sind
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    // Wenn Argumente vorhanden sind (außer dem Programmnamen), übergebe sie an die CLI
    if (argc > 1) {
        LocalFree(argv); // CommandLineToArgvW-Speicher freigeben
        
        // Konvertiere wchar_t** zu char*[]
        std::vector<std::string> argStrings;
        std::vector<char*> args;
        
        // Erstes Argument ist der Programmname
        argStrings.push_back("encrypt.exe");
        
        // Parse command line to get arguments
        int cmdArgc;
        LPWSTR* cmdArgv = CommandLineToArgvW(GetCommandLineW(), &cmdArgc);
        
        for (int i = 1; i < cmdArgc; i++) {
            // Convert wchar_t* to char*
            int size = WideCharToMultiByte(CP_UTF8, 0, cmdArgv[i], -1, NULL, 0, NULL, NULL);
            std::string arg(size, 0);
            WideCharToMultiByte(CP_UTF8, 0, cmdArgv[i], -1, &arg[0], size, NULL, NULL);
            arg.resize(strlen(arg.c_str())); // Resize to actual length
            argStrings.push_back(arg);
        }
        
        LocalFree(cmdArgv);
        
        // Fill args array with C-style strings
        for (auto& s : argStrings) {
            args.push_back(&s[0]);
        }
        
        // Call the CLI interface
        return encrypt::ui::run(args.size(), args.data());
    }
    
    // Keine Argumente - zeige Drag-and-Drop-Fenster
    
    // Registeriere Fensterklasse
    WNDCLASSA wc;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = WindowProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = "EncryptDropClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    
    if (!RegisterClassA(&wc)) {
        MessageBoxA(NULL, "Fensterklasse konnte nicht registriert werden.", "Fehler", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    // Erstelle Fenster
    HWND hwnd = CreateWindowExA(
        0,
        "EncryptDropClass",
        "Encrypt - Dateien per Drag & Drop verschlüsseln",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        500, 300,
        NULL, NULL, hInstance, NULL
    );
    
    if (!hwnd) {
        MessageBoxA(NULL, "Fenster konnte nicht erstellt werden.", "Fehler", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    // Fenster anzeigen
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    // Nachrichtenschleife
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return static_cast<int>(msg.wParam);
}

#endif // _WIN32