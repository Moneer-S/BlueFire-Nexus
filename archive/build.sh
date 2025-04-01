#!/bin/bash
# archive/build.sh
# (Originally scripts/build.sh)

# Note: This script uses Nuitka to compile a specific Python file 
# (originally src/core/polymorphic_engine.py, now archived) into an executable.
# It is currently OUTDATED and requires significant updates if this workflow is needed.
# Dependencies: nuitka3, openssl, osslsigncode, MinGW (for Windows target)

echo "[Archive Build Script - WARNING]"
echo "This script is outdated and likely non-functional without updates."
echo "It targets archived code (archive/polymorphic_engine.py) and removed directories (src.operators)."
exit 1 # Prevent accidental execution

# --- Original (Non-functional) Commands Below --- 

set -e

# Define target file (adjust path to archived location if attempting to revive)
TARGET_PY="archive/polymorphic_engine.py"
ICON_PATH="assets/fake_icon.ico" # Ensure this path is valid
OUTPUT_DIR="dist_archive"

# Check if target Python file exists
if [ ! -f "$TARGET_PY" ]; then
    echo "Error: Target Python file not found: $TARGET_PY" 
    exit 1
fi

# Nuitka compilation (Outdated paths)
nuitka3 --onefile --mingw64 --enable-plugin=multiprocessing \
--include-package=src.core `# This path might still be relevant? Needs check.` \
`# --include-package=src.operators # This path was removed` \
--output-dir="$OUTPUT_DIR" --remove-output \
`# --windows-icon-from-ico=$ICON_PATH # Uncomment if icon exists` \
"$TARGET_PY"

# Output executable name depends on the Python file name
OUTPUT_EXE="$OUTPUT_DIR/polymorphic_engine.exe"

if [ ! -f "$OUTPUT_EXE" ]; then
    echo "Error: Nuitka compilation failed or output file not found." 
    exit 1
fi

# Generate fake certificate
CERT_KEY="key_archive.pem"
CERT_PEM="cert_archive.pem"
openssl req -x509 -newkey rsa:4096 -keyout "$CERT_KEY" -out "$CERT_PEM" -days 365 -nodes \
-subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com"

# Combine key and cert into PKCS12 (optional, depends on signer)
# openssl pkcs12 -export -out cert.p12 -inkey $CERT_KEY -in $CERT_PEM -passout pass:password123

# Sign binary (requires osslsigncode setup)
SIGNED_EXE="$OUTPUT_DIR/signed_engine.exe"
echo "Attempting to sign (requires osslsigncode and potentially a .p12 file)..."
# osslsigncode sign -pkcs12 cert.p12 -pass password123 \
#   -in "$OUTPUT_EXE" -out "$SIGNED_EXE"
# Or sign with key/cert pair:
# osslsigncode sign -certs $CERT_PEM -key $CERT_KEY -in "$OUTPUT_EXE" -out "$SIGNED_EXE"
echo "(Signing command commented out)"

echo "Archived build script finished (simulation)." 