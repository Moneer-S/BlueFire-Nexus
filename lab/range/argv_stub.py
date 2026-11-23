#!/usr/bin/python3 -I
"""Stand-in for sh and bash in the atomic-parity job. It runs nothing: it writes the
argument vector it was started with, byte for byte from /proc/self/cmdline, into the
folder BLUEFIRE_PARITY_CALLS names, and exits 0.

The kernel starts it as `/usr/bin/python3 -I <this file> <arguments>`, so the first three
elements of the vector are the interpreter, its option and this file's path.
"""

import json
import os

with open("/proc/self/cmdline", "rb") as handle:
    vector = handle.read().split(b"\0")[:-1]
record = {"cmdline": [element.hex() for element in vector]}
folder = os.environ["BLUEFIRE_PARITY_CALLS"]
number = 0
while True:
    try:
        written = os.open(os.path.join(folder, f"{number:04d}.json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        break
    except FileExistsError:
        number += 1
with os.fdopen(written, "w", encoding="ascii") as handle:
    json.dump(record, handle)
