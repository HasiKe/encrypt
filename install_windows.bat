@echo off
echo Encrypt Windows-Installation
echo ===========================

rem Zielverzeichnis festlegen
set INSTALL_DIR=%USERPROFILE%\Encrypt

rem Verzeichnis erstellen, falls es nicht existiert
if not exist "%INSTALL_DIR%" (
    echo Erstelle Installationsverzeichnis...
    mkdir "%INSTALL_DIR%"
)

rem Kopiere die ausführbare Datei
echo Kopiere encrypt.exe...
copy /Y encrypt.exe "%INSTALL_DIR%\encrypt.exe"

rem Erstelle Desktop-Verknüpfung
echo Erstelle Desktop-Verknüpfung...
powershell "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\Encrypt.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\encrypt.exe'; $Shortcut.Save()"

rem Setze PATH-Umgebungsvariable
echo Füge Programm zur PATH-Umgebungsvariable hinzu...
setx PATH "%PATH%;%INSTALL_DIR%"

echo.
echo Installation abgeschlossen!
echo Das Programm wurde nach "%INSTALL_DIR%" installiert und kann über die Desktop-Verknüpfung gestartet werden.
echo.
echo Drücken Sie eine beliebige Taste, um das Installationsprogramm zu beenden...
pause > nul