@echo off
rem Builds "Password Manager" as a Windows installer (.exe).
rem Needs: JDK 17+ (jpackage) and the free WiX Toolset 3.x (https://wixtoolset.org) on PATH.
rem Optional: set APP_VERSION=1.2.3 before running (default 1.0.0).
setlocal
cd /d "%~dp0"
if "%APP_VERSION%"=="" set APP_VERSION=1.0.0

if exist build rmdir /s /q build
mkdir build\classes
mkdir build\dist

echo [1/4] Compiling...
javac -encoding UTF-8 -d build\classes src\PasswordManager.java || goto :error

echo [2/4] Creating icons...
java -cp build\classes PasswordManager --write-icons build\icons || goto :error

echo [3/4] Creating JAR...
jar --create --file build\dist\PasswordManager.jar --main-class PasswordManager -C build\classes . || goto :error

echo [4/4] Building installer (version %APP_VERSION%)...
jpackage --type exe --name "Password Manager" --app-version %APP_VERSION% ^
  --description "Encrypted password manager" --vendor "Password Manager" ^
  --input build\dist --main-jar PasswordManager.jar --main-class PasswordManager ^
  --icon build\icons\icon.ico --dest build\installer ^
  --win-menu --win-shortcut --win-dir-chooser ^
  --win-upgrade-uuid eaaa04c0-677c-4354-abaf-e216c2dc75ca || goto :error

echo.
echo Done. Your installer is in build\installer
exit /b 0

:error
echo.
echo Build failed. See the messages above.
exit /b 1
