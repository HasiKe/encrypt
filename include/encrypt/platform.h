#ifndef ENCRYPT_PLATFORM_H
#define ENCRYPT_PLATFORM_H

#include <string>
#include <functional>

namespace encrypt {
namespace platform {

/**
 * @brief Zeigt eine Nachricht an den Benutzer an
 * 
 * @param message Die anzuzeigende Nachricht
 * @param title Der Titel der Nachricht (für Dialogfenster)
 */
void showMessage(const std::string& message, const std::string& title = "Encryption");

/**
 * @brief Fordert ein Passwort vom Benutzer an
 * 
 * @param prompt Text für die Passwortabfrage
 * @return Das eingegebene Passwort
 */
std::string getPassword(const std::string& prompt = "Bitte geben Sie das Passwort ein:");

/**
 * @brief Zeigt einen Fortschrittsbalken an
 * 
 * @param progress Wert zwischen 0.0 und 1.0
 * @param operation Beschreibung des Vorgangs
 */
void updateProgress(float progress, const std::string& operation);

/**
 * @brief Korrigiert Pfadtrennzeichen für das aktuelle Betriebssystem
 * 
 * @param path Der zu korrigierende Pfad
 * @return Der korrigierte Pfad
 */
std::string normalizePath(const std::string& path);

/**
 * @brief Extrahiert den Dateinamen aus einem Pfad
 * 
 * @param path Der vollständige Pfad
 * @return Der Dateiname ohne Pfad
 */
std::string getFileName(const std::string& path);

/**
 * @brief Prüft, ob eine Datei existiert
 * 
 * @param path Pfad zur Datei
 * @return true wenn die Datei existiert, sonst false
 */
bool fileExists(const std::string& path);

} // namespace platform
} // namespace encrypt

#endif // ENCRYPT_PLATFORM_H