#!/bin/bash
# Builds "Password Manager" for Linux. Run on Linux with JDK 17+.
# Usage: ./build-linux.sh [deb|rpm|app-image]   (default: deb; use rpm on Fedora/openSUSE)
# deb needs dpkg + fakeroot; rpm needs rpm-build. app-image needs nothing extra.
# Optional: APP_VERSION=1.2.3 ./build-linux.sh   (default 1.0.0)
set -euo pipefail
cd "$(dirname "$0")"
TYPE="${1:-deb}"
VERSION="${APP_VERSION:-1.0.0}"

rm -rf build
mkdir -p build/classes build/dist

echo "[1/4] Compiling..."
javac -encoding UTF-8 -d build/classes src/PasswordManager.java

echo "[2/4] Creating icons..."
java -cp build/classes PasswordManager --write-icons build/icons

echo "[3/4] Creating JAR..."
jar --create --file build/dist/PasswordManager.jar --main-class PasswordManager -C build/classes .

echo "[4/4] Building $TYPE (version $VERSION)..."
EXTRA=()
if [ "$TYPE" != "app-image" ]; then
  EXTRA=(--linux-shortcut --linux-menu-group "Utility;Security" --linux-package-name password-manager)
fi
jpackage --type "$TYPE" --name "Password Manager" --app-version "$VERSION" \
  --description "Encrypted password manager" \
  --input build/dist --main-jar PasswordManager.jar --main-class PasswordManager \
  --icon build/icons/icon.png --dest build/installer "${EXTRA[@]}"

echo
echo "Done. Your package is in build/installer"
