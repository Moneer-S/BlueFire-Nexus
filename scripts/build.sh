#!/bin/bash
# Obfuscated build script
set -e

nuitka3 --onefile --mingw64 --enable-plugin=multiprocessing \
--include-package=src.core --include-package=src.operators \
--output-dir=dist --remove-output \
--windows-icon-from-ico=assets/fake_icon.ico \
src/core/polymorphic_engine.py

# Generate fake certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
-subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com"

# Sign binary
osslsigncode sign -pkcs12 cert.p12 -pass password123 \
-in dist/polymorphic_engine.exe -out dist/signed_engine.exe