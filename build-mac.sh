#!/bin/bash
# Builds "Password Manager" as a macOS disk image (.dmg). Run on a Mac with JDK 17+.
# Optional: APP_VERSION=1.2.3 ./build-mac.sh   (default 1.0.0)
set -euo pipefail
cd "$(dirname "$0")"
VERSION="${APP_VERSION:-1.0.0}"

rm -rf build
mkdir -p build/classes build/dist

echo "[1/4] Compiling..."
javac -encoding UTF-8 -d build/classes src/PasswordManager.java

echo "[2/4] Creating icons..."
java -cp build/classes PasswordManager --write-icons build/icons

echo "[3/4] Creating JAR..."
jar --create --file build/dist/PasswordManager.jar --main-class PasswordManager -C build/classes .

echo "[4/4] Building .dmg (version $VERSION)..."
jpackage --type dmg --name "Password Manager" --app-version "$VERSION" \
  --description "Encrypted password manager" \
  --input build/dist --main-jar PasswordManager.jar --main-class PasswordManager \
  --icon build/icons/icon.icns --dest build/installer \
  --mac-package-name "Password Manager" \
  --java-options "-Xdock:name=Password Manager"

echo
echo "Done. Your installer is in build/installer"
echo "Unsigned apps need: right-click the app > Open (first launch only)."
