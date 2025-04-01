# archive/gpu_payload.py
# (Originally src/modules/gpu_payload.py)
import pycuda.driver as cuda
import pycuda.autoinit
import logging

class GPUPayload:
    """
    Demonstrates storing payloads in GPU memory to reduce detection.
    Requires pycuda: pip install pycuda
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        try:
            self.device = cuda.Device(0)
            self.context = self.device.make_context()
        except Exception as e:
            self.logger.error(f"Failed to initialize CUDA: {e}")
            raise
    
    def load(self, payload: bytes):
        if not payload:
            raise ValueError("Payload is empty.")
        try:
            mem = cuda.mem_alloc(len(payload))
            cuda.memcpy_htod(mem, payload)
            self.logger.info(f"Payload of size {len(payload)} bytes loaded into GPU memory.")
            return mem # Return pointer/handle to GPU memory
        except Exception as e:
            self.logger.error(f"Failed to load payload into GPU memory: {e}")
            raise
    
    def cleanup(self):
        """
        Pop the CUDA context to avoid memory leaks.
        """
        try:
            self.context.pop()
            self.logger.info("CUDA context popped.")
        except Exception as e:
            self.logger.warning(f"Failed to pop CUDA context: {e}") 