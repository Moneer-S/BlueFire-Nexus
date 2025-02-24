# src/legal_safeguards.py
import os

def secure_wipe(path):
    """
    Overwrites the file with random data, then deletes it.
    Effectiveness depends on filesystem and hardware specifics.
    """
    if not os.path.exists(path):
        return
    with open(path, "ba+", buffering=0) as f:
        length = f.tell()
        f.seek(0)
        f.write(os.urandom(length))
        f.flush()
        os.fsync(f.fileno())
    os.remove(path)
