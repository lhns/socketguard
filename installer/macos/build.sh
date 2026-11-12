#!/usr/bin/env bash
# Build the macOS installer package (unsigned).
#
#   installer/macos/build.sh <version> [outdir]      # after ./build.sh, on macOS
#
# Payload: /usr/local/bin/{socketguard-daemon,socketguard} and /Applications/SocketGuard.app
# (the UI binary, assembled by hand: Tauri's bundler would need @tauri-apps/cli, a bundle
# section in tauri.conf.json and a second build path next to build.sh, for an Info.plist and an
# icon). The app finds the CLI and the daemon in /usr/local/bin. postinstall runs
# `socketguard-daemon service install`. Files in installer/payload/macos (README.md and
# .gitkeep excepted) go to /usr/local/lib/socketguard/third_party/ (installer/payload/README.md).
#
# SIGNING (not done yet): see docs/packaging.md for the secrets. Where it would go is marked
# SIGN below.
set -euo pipefail
cd "$(dirname "$0")/../.."

version="${1:?usage: build.sh <version> [outdir]}"
out="${2:-dist}"
bin="${BIN_DIR:-target/release}"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

root="$work/root"
app="$root/Applications/SocketGuard.app"
mkdir -p "$root/usr/local/bin" "$app/Contents/MacOS" "$app/Contents/Resources"
install -m 0755 "$bin/socketguard-daemon" "$bin/socketguard" "$root/usr/local/bin/"
install -m 0755 "$bin/socketguard-ui" "$app/Contents/MacOS/socketguard-ui"
cp ui/src-tauri/icons/icon.icns "$app/Contents/Resources/icon.icns"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>SocketGuard</string>
  <key>CFBundleDisplayName</key><string>SocketGuard</string>
  <key>CFBundleIdentifier</key><string>com.socketguard.desktop</string>
  <key>CFBundleExecutable</key><string>socketguard-ui</string>
  <key>CFBundleIconFile</key><string>icon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleVersion</key><string>$version</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

if [ -n "$(find installer/payload/macos -type f ! -name .gitkeep ! -name README.md -print -quit)" ]; then
    mkdir -p "$root/usr/local/lib/socketguard/third_party"
    cp -a installer/payload/macos/. "$root/usr/local/lib/socketguard/third_party/"
    rm -f "$root/usr/local/lib/socketguard/third_party/.gitkeep" "$root/usr/local/lib/socketguard/third_party/README.md"
fi

# An ad-hoc signature: Apple silicon will not run an unsigned bundle. It is not an identity.
codesign --force --deep --sign - "$app"
# SIGN: with a Developer ID Application certificate in the keychain, replace the line above by
#   codesign --force --deep --options runtime --timestamp --sign "$APPLE_SIGNING_IDENTITY" "$app"
# and sign /usr/local/bin/* the same way before pkgbuild.

cp -R installer/macos/scripts "$work/scripts"
chmod +x "$work/scripts/"*
# A bundle is "relocatable" by default: an upgrade then updates the app wherever Launch Services
# finds a copy of it (a build directory, a moved app) instead of /Applications.
pkgbuild --analyze --root "$root" "$work/components.plist"
i=0
while /usr/libexec/PlistBuddy -c "Print :$i" "$work/components.plist" >/dev/null 2>&1; do
    /usr/libexec/PlistBuddy -c "Set :$i:BundleIsRelocatable false" "$work/components.plist"
    i=$((i + 1))
done
pkgbuild --root "$root" --identifier de.lhns.socketguard --version "$version" \
    --install-location / --scripts "$work/scripts" --component-plist "$work/components.plist" \
    --ownership recommended "$work/component.pkg"
# SIGN: productbuild --sign "$APPLE_INSTALLER_IDENTITY" (Developer ID Installer), then
#   xcrun notarytool submit ... --wait && xcrun stapler staple
productbuild --package "$work/component.pkg" "$out/SocketGuard-$version-$(uname -m).pkg"
ls -l "$out"
