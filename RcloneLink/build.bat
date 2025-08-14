@echo off
REM --- Clean up old build files ---
set APP_NAME=RcloneLink

echo Cleaning up old build files...
if exist build rmdir /s /q build
if exist %APP_NAME%.spec del /q %APP_NAME%.spec

echo Starting PyInstaller build for %APP_NAME%...

pyinstaller --name "RcloneLink" ^
    --noconfirm ^
    --clean ^
    --onefile ^
    --windowed ^
    --icon="icon.ico" ^
    --version-file "file_version_info.txt" ^
    --add-binary "rclone.exe;." ^
    --add-data "winfsp-2.1.25156.msi;." ^
    --add-data "icon.png;." ^
    --hidden-import "win32api" ^
    --hidden-import "winreg" ^
    --hidden-import "PySide6.QtSvg" ^
    RcloneLink.py

pause