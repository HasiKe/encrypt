@echo off
echo Encrypt Windows Installation
echo ===========================

rem Set target directory
set INSTALL_DIR=%USERPROFILE%\Encrypt

rem Create directory if it doesn't exist
if not exist "%INSTALL_DIR%" (
    echo Creating installation directory...
    mkdir "%INSTALL_DIR%"
)

rem Copy the executable
echo Copying encrypt.exe...
copy /Y encrypt.exe "%INSTALL_DIR%\encrypt.exe"

rem Create desktop shortcut
echo Creating desktop shortcut...
powershell "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\Encrypt.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\encrypt.exe'; $Shortcut.Save()"

rem Set PATH environment variable
echo Adding program to PATH environment variable...
setx PATH "%PATH%;%INSTALL_DIR%"

echo.
echo Installation complete!
echo The program has been installed to "%INSTALL_DIR%" and can be started using the desktop shortcut.
echo.
echo Press any key to exit the installer...
pause > nul