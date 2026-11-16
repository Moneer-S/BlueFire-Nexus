#!/bin/sh
# Harmless commands. Their telemetry shows how a sensor reports nested shells,
# children that detach from their parent, and files created and removed.
# Usage: probes.sh <nonce>
nonce="$1"
/usr/bin/true "$nonce-direct"
sh -c "sh -c '/usr/bin/true $nonce-nested'"
(setsid sh -c "sleep 1; /usr/bin/true $nonce-detached" > /dev/null 2>&1 &)
python3 -c "import os, sys; os.fork() or (os.setsid(), os.fork() and os._exit(0), os.execv('/usr/bin/true', ['true', sys.argv[1]]))" "$nonce-doublefork"
touch "/tmp/$nonce.file"
rm "/tmp/$nonce.file"
sleep 2
