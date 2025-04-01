#include <iostream>

// UI-Module-Export-Funktionen
namespace encrypt {
namespace ui {
    int run(int argc, char* argv[]);
}
}

/**
 * @brief Haupteinstiegspunkt der Anwendung
 * 
 * Diese Funktion leitet die Programmargumente an die UI-Implementierung weiter.
 * 
 * @param argc Anzahl der Kommandozeilenargumente
 * @param argv Array der Kommandozeilenargumente
 * @return int Programm-Exit-Code
 */
int main(int argc, char* argv[]) {
    try {
        return encrypt::ui::run(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Unerwarteter Fehler: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unbekannter Fehler aufgetreten!" << std::endl;
        return 1;
    }
}