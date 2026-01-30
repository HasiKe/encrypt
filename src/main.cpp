/**
 * @file main.cpp
 * @brief Application entry point
 * @author HasiKe
 * @version 2.0.0
 * 
 * Delegates to platform-specific main functions based on
 * build configuration and runtime environment.
 */

#include "encrypt/platform.h"
#include <iostream>

#ifdef _WIN32
#include <windows.h>

// Windows GUI entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;  // Unused
    
    // If started from command line with arguments, use CLI mode
    int argc = __argc;
    char** argv = __argv;
    
    if (argc > 1) {
        return encrypt::platform::cliMain(argc, argv);
    }
    
    // GUI mode
    return encrypt::platform::guiMain(hInstance, lpCmdLine, nCmdShow);
}

// Also provide console entry point for CLI builds
int main(int argc, char* argv[]) {
    return encrypt::platform::cliMain(argc, argv);
}

#else
// Linux/Unix entry point
int main(int argc, char* argv[]) {
    return encrypt::platform::cliMain(argc, argv);
}
#endif
