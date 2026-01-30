/**
 * @file windows.cpp
 * @brief Windows platform implementation
 * @author HasiKe
 * @version 2.0.0
 * 
 * Provides platform-specific implementations for Windows
 * including GUI dialogs and drag-and-drop support.
 */

#ifdef _WIN32

#include "encrypt/platform.h"
#include <windows.h>
#include <commctrl.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

namespace encrypt {
namespace platform {

//=============================================================================
// Constants
//=============================================================================

static const wchar_t* WINDOW_CLASS = L"EncryptDropWindow";
static const wchar_t* WINDOW_TITLE = L"Encrypt - Drop Files Here";
static const int WINDOW_WIDTH = 400;
static const int WINDOW_HEIGHT = 300;

static bool g_colorEnabled = true;
static HWND g_progressWnd = nullptr;
static HWND g_progressBar = nullptr;
static HWND g_statusLabel = nullptr;

//=============================================================================
// Utility Functions
//=============================================================================

static std::string wideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return "";
    
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, 
                                    nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, 
                        &result[0], size, nullptr, nullptr);
    return result;
}

static std::wstring utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    std::wstring result(size - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &result[0], size);
    return result;
}

//=============================================================================
// User Interaction
//=============================================================================

void showMessage(const std::string& message, const std::string& title,
                 bool isError) {
    std::wstring wMessage = utf8ToWide(message);
    std::wstring wTitle = utf8ToWide(title.empty() ? "Encrypt" : title);
    
    UINT type = MB_OK | (isError ? MB_ICONERROR : MB_ICONINFORMATION);
    MessageBoxW(nullptr, wMessage.c_str(), wTitle.c_str(), type);
}

std::string getPassword(const std::string& prompt, bool confirm) {
    // Simple dialog for password input
    // In production, use a proper password dialog
    
    HWND hwnd = GetConsoleWindow();
    
    // Create password dialog
    std::string password;
    
    // For console mode, read from stdin with hidden input
    if (hwnd) {
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(hStdin, &mode);
        SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);
        
        std::cout << prompt;
        std::getline(std::cin, password);
        std::cout << std::endl;
        
        if (confirm) {
            std::string confirmPwd;
            std::cout << "Confirm password: ";
            std::getline(std::cin, confirmPwd);
            std::cout << std::endl;
            
            if (password != confirmPwd) {
                std::cerr << "Passwords do not match!" << std::endl;
                SetConsoleMode(hStdin, mode);
                return "";
            }
        }
        
        SetConsoleMode(hStdin, mode);
    }
    
    return password;
}

SecurityLevel getSecurityLevel() {
    // Use MessageBox to select security level
    std::wstring message = 
        L"Select security level:\n\n"
        L"1 - Basic (AES-128, fast)\n"
        L"2 - Standard (AES-256) [Recommended]\n"
        L"3 - Enhanced (AES-256, strong KDF)\n"
        L"4 - High (AES-256, Argon2)\n"
        L"5 - Maximum (AES-256 + ChaCha20)\n\n"
        L"Enter level (1-5):";
    
    // For simplicity, return default
    // In production, use a proper dialog
    return SecurityLevel::LEVEL_2;
}

bool askConfirmation(const std::string& question, bool defaultYes) {
    std::wstring wQuestion = utf8ToWide(question);
    
    int result = MessageBoxW(nullptr, wQuestion.c_str(), L"Confirm",
                             MB_YESNO | MB_ICONQUESTION | 
                             (defaultYes ? MB_DEFBUTTON1 : MB_DEFBUTTON2));
    
    return result == IDYES;
}

void showProgress(uint64_t current, uint64_t total, const std::string& message) {
    if (g_progressBar) {
        int percent = total > 0 ? static_cast<int>((current * 100) / total) : 0;
        SendMessage(g_progressBar, PBM_SETPOS, percent, 0);
    }
    
    if (g_statusLabel && !message.empty()) {
        std::wstring wMessage = utf8ToWide(message);
        SetWindowTextW(g_statusLabel, wMessage.c_str());
    }
    
    // Process messages to keep UI responsive
    MSG msg;
    while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void clearProgress() {
    if (g_progressBar) {
        SendMessage(g_progressBar, PBM_SETPOS, 0, 0);
    }
    if (g_statusLabel) {
        SetWindowTextW(g_statusLabel, L"Ready");
    }
}

//=============================================================================
// File System Operations
//=============================================================================

std::string normalizePath(const std::string& path) {
    std::string normalized = path;
    
    // Convert forward slashes to backslashes
    for (char& c : normalized) {
        if (c == '/') c = '\\';
    }
    
    // Remove trailing backslashes
    while (normalized.length() > 1 && normalized.back() == '\\') {
        normalized.pop_back();
    }
    
    return normalized;
}

bool fileExists(const std::string& path) {
    std::wstring wPath = utf8ToWide(normalizePath(path));
    DWORD attrs = GetFileAttributesW(wPath.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES;
}

bool isDirectory(const std::string& path) {
    std::wstring wPath = utf8ToWide(normalizePath(path));
    DWORD attrs = GetFileAttributesW(wPath.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES) && 
           (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

uint64_t getFileSize(const std::string& path) {
    std::wstring wPath = utf8ToWide(normalizePath(path));
    
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(wPath.c_str(), GetFileExInfoStandard, &fad)) {
        return 0;
    }
    
    LARGE_INTEGER size;
    size.HighPart = fad.nFileSizeHigh;
    size.LowPart = fad.nFileSizeLow;
    return static_cast<uint64_t>(size.QuadPart);
}

std::string getFilename(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

std::string getDirectory(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos) {
        return ".";
    }
    return path.substr(0, pos);
}

std::string getExtension(const std::string& path) {
    std::string filename = getFilename(path);
    size_t pos = filename.find_last_of('.');
    if (pos == std::string::npos || pos == 0) {
        return "";
    }
    return filename.substr(pos);
}

std::string removeExtension(const std::string& path) {
    std::string ext = getExtension(path);
    if (ext.empty()) {
        return path;
    }
    return path.substr(0, path.length() - ext.length());
}

bool createDirectory(const std::string& path) {
    std::wstring wPath = utf8ToWide(normalizePath(path));
    
    // Use SHCreateDirectoryEx to create parent directories
    int result = SHCreateDirectoryExW(nullptr, wPath.c_str(), nullptr);
    return result == ERROR_SUCCESS || result == ERROR_ALREADY_EXISTS;
}

std::vector<std::string> listFiles(const std::string& path, bool recursive) {
    std::vector<std::string> files;
    std::string normalized = normalizePath(path);
    std::wstring wPath = utf8ToWide(normalized + "\\*");
    
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(wPath.c_str(), &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return files;
    }
    
    do {
        std::wstring wName = findData.cFileName;
        if (wName == L"." || wName == L"..") {
            continue;
        }
        
        std::string name = wideToUtf8(wName);
        std::string fullPath = normalized + "\\" + name;
        
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (recursive) {
                auto subFiles = listFiles(fullPath, true);
                files.insert(files.end(), subFiles.begin(), subFiles.end());
            }
        } else {
            files.push_back(fullPath);
        }
    } while (FindNextFileW(hFind, &findData));
    
    FindClose(hFind);
    return files;
}

bool deleteFile(const std::string& path) {
    std::wstring wPath = utf8ToWide(normalizePath(path));
    return DeleteFileW(wPath.c_str()) != 0;
}

std::string getTempDirectory() {
    wchar_t buffer[MAX_PATH + 1];
    DWORD len = GetTempPathW(MAX_PATH + 1, buffer);
    if (len > 0) {
        return wideToUtf8(std::wstring(buffer, len));
    }
    return "C:\\Temp";
}

std::string getTempFilename(const std::string& prefix) {
    std::wstring wTempDir = utf8ToWide(getTempDirectory());
    std::wstring wPrefix = utf8ToWide(prefix);
    
    wchar_t buffer[MAX_PATH + 1];
    if (GetTempFileNameW(wTempDir.c_str(), wPrefix.c_str(), 0, buffer)) {
        return wideToUtf8(buffer);
    }
    
    // Fallback
    return getTempDirectory() + prefix + std::to_string(GetCurrentProcessId());
}

//=============================================================================
// High-Level Operations
//=============================================================================

EncryptionResult processFile(const std::string& inputPath,
                             const std::string& password,
                             SecurityLevel level) {
    std::string normalized = normalizePath(inputPath);
    
    if (!fileExists(normalized)) {
        EncryptionResult result;
        result.success = false;
        result.errorMessage = "File not found: " + normalized;
        return result;
    }
    
    std::string pwd = password;
    if (pwd.empty()) {
        bool isEncrypted = getExtension(normalized) == Constants::ENCRYPTED_EXTENSION;
        pwd = getPassword(isEncrypted ? "Enter password: " : "Enter password: ",
                          !isEncrypted);
        if (pwd.empty()) {
            EncryptionResult result;
            result.success = false;
            result.errorMessage = "Password required";
            return result;
        }
    }
    
    bool decrypt = false;
    if (getExtension(normalized) == Constants::ENCRYPTED_EXTENSION) {
        decrypt = true;
    } else if (Crypto::isEncryptedFile(normalized)) {
        decrypt = true;
    }
    
    ProgressCallback progress = [](uint64_t current, uint64_t total,
                                   const std::string& filename) -> bool {
        showProgress(current, total, filename);
        return true;
    };
    
    EncryptionResult result;
    
    if (decrypt) {
        auto header = Crypto::readFileHeader(normalized);
        if (header.isFolder) {
            result = Crypto::decryptFolder(normalized, pwd, "", progress);
        } else {
            result = Crypto::decryptFile(normalized, pwd, "", progress);
        }
    } else {
        SecurityLevel lvl = level;
        if (lvl == SecurityLevel::LEVEL_1) {
            lvl = getSecurityLevel();
        }
        
        if (isDirectory(normalized)) {
            result = Crypto::encryptFolder(normalized, pwd, lvl, "", progress);
        } else {
            result = Crypto::encryptFile(normalized, pwd, lvl, "", progress);
        }
    }
    
    clearProgress();
    return result;
}

std::vector<EncryptionResult> processFiles(const std::vector<std::string>& paths,
                                           const std::string& password,
                                           SecurityLevel level) {
    std::vector<EncryptionResult> results;
    
    for (const auto& path : paths) {
        results.push_back(processFile(path, password, level));
    }
    
    return results;
}

//=============================================================================
// System Utilities
//=============================================================================

std::string getPlatformName() {
    return "Windows";
}

bool isGuiAvailable() {
    return true;  // Always available on Windows
}

std::string getCurrentDirectory() {
    wchar_t buffer[MAX_PATH + 1];
    if (GetCurrentDirectoryW(MAX_PATH + 1, buffer)) {
        return wideToUtf8(buffer);
    }
    return ".";
}

void setConsoleTitle(const std::string& title) {
    std::wstring wTitle = utf8ToWide(title);
    SetConsoleTitleW(wTitle.c_str());
}

void clearScreen() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD count;
    DWORD cellCount;
    COORD homeCoords = {0, 0};
    
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;
    cellCount = csbi.dwSize.X * csbi.dwSize.Y;
    
    FillConsoleOutputCharacter(hConsole, ' ', cellCount, homeCoords, &count);
    FillConsoleOutputAttribute(hConsole, csbi.wAttributes, cellCount, homeCoords, &count);
    SetConsoleCursorPosition(hConsole, homeCoords);
}

void setColorOutput(bool enable) {
    g_colorEnabled = enable;
    
    if (enable) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(hConsole, &mode);
        SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
}

void printColored(const std::string& text, const std::string& colorCode) {
    if (g_colorEnabled) {
        std::cout << "\033[" << colorCode << "m" << text << "\033[0m";
    } else {
        std::cout << text;
    }
}

//=============================================================================
// GUI Window Implementation
//=============================================================================

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // Accept drag and drop
            DragAcceptFiles(hwnd, TRUE);
            
            // Create status label
            g_statusLabel = CreateWindowW(L"STATIC", L"Drop files here to encrypt",
                WS_CHILD | WS_VISIBLE | SS_CENTER,
                10, 10, WINDOW_WIDTH - 40, 30, hwnd, nullptr,
                GetModuleHandle(nullptr), nullptr);
            
            // Create progress bar
            g_progressBar = CreateWindowW(PROGRESS_CLASSW, nullptr,
                WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                20, 50, WINDOW_WIDTH - 60, 25, hwnd, nullptr,
                GetModuleHandle(nullptr), nullptr);
            
            SendMessage(g_progressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
            break;
        }
        
        case WM_DROPFILES: {
            HDROP hDrop = reinterpret_cast<HDROP>(wParam);
            UINT fileCount = DragQueryFileW(hDrop, 0xFFFFFFFF, nullptr, 0);
            
            std::vector<std::string> files;
            for (UINT i = 0; i < fileCount; ++i) {
                wchar_t buffer[MAX_PATH + 1];
                if (DragQueryFileW(hDrop, i, buffer, MAX_PATH + 1)) {
                    files.push_back(wideToUtf8(buffer));
                }
            }
            DragFinish(hDrop);
            
            if (!files.empty()) {
                // Get password
                std::string password = getPassword("Enter password: ", true);
                if (!password.empty()) {
                    // Process files
                    auto results = processFiles(files, password, SecurityLevel::LEVEL_2);
                    
                    // Show results
                    int success = 0, failed = 0;
                    for (const auto& result : results) {
                        if (result.success) success++;
                        else failed++;
                    }
                    
                    std::wstring message = L"Processed " + std::to_wstring(files.size()) +
                                           L" file(s)\nSuccess: " + std::to_wstring(success) +
                                           L"\nFailed: " + std::to_wstring(failed);
                    
                    MessageBoxW(hwnd, message.c_str(), L"Complete", 
                               failed > 0 ? MB_ICONWARNING : MB_ICONINFORMATION);
                }
            }
            break;
        }
        
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int guiMain(void* hInstance, const char* lpCmdLine, int nCmdShow) {
    HINSTANCE hInst = static_cast<HINSTANCE>(hInstance);
    (void)lpCmdLine;
    
    // Initialize common controls
    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_PROGRESS_CLASS};
    InitCommonControlsEx(&icc);
    
    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = WINDOW_CLASS;
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
    
    if (!RegisterClassExW(&wc)) {
        return 1;
    }
    
    // Create window
    HWND hwnd = CreateWindowExW(
        WS_EX_ACCEPTFILES,
        WINDOW_CLASS,
        WINDOW_TITLE,
        WS_OVERLAPPEDWINDOW & ~(WS_MAXIMIZEBOX | WS_THICKFRAME),
        CW_USEDEFAULT, CW_USEDEFAULT,
        WINDOW_WIDTH, WINDOW_HEIGHT,
        nullptr, nullptr, hInst, nullptr
    );
    
    if (!hwnd) {
        return 1;
    }
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return static_cast<int>(msg.wParam);
}

} // namespace platform
} // namespace encrypt

#endif // _WIN32
