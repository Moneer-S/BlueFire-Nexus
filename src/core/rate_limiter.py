import time
from typing import Dict, Optional
from collections import defaultdict
from threading import Lock
from ..core.logger import get_logger

logger = get_logger(__name__)

class RateLimiter:
    """Rate limiter for controlling request rates."""
    
    def __init__(self, requests_per_minute: int = 60, max_concurrent: int = 10):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_minute: Maximum requests per minute
            max_concurrent: Maximum concurrent requests
        """
        self.requests_per_minute = requests_per_minute
        self.max_concurrent = max_concurrent
        self.requests: Dict[str, list] = defaultdict(list)
        self.concurrent_requests = 0
        self.lock = Lock()
    
    def can_proceed(self, client_id: str) -> bool:
        """
        Check if a request can proceed.
        
        Args:
            client_id: Unique identifier for the client
            
        Returns:
            bool: True if request can proceed, False otherwise
        """
        current_time = time.time()
        
        with self.lock:
            # Clean old requests
            self.requests[client_id] = [
                req_time for req_time in self.requests[client_id]
                if current_time - req_time < 60
            ]
            
            # Check rate limit
            if len(self.requests[client_id]) >= self.requests_per_minute:
                logger.warning(f"Rate limit exceeded for client {client_id}")
                return False
            
            # Check concurrent requests
            if self.concurrent_requests >= self.max_concurrent:
                logger.warning("Maximum concurrent requests reached")
                return False
            
            # Update counters
            self.requests[client_id].append(current_time)
            self.concurrent_requests += 1
            
            return True
    
    def release(self) -> None:
        """Release a concurrent request slot."""
        with self.lock:
            if self.concurrent_requests > 0:
                self.concurrent_requests -= 1
    
    def reset(self, client_id: Optional[str] = None) -> None:
        """
        Reset rate limiting for a client or all clients.
        
        Args:
            client_id: Optional client ID to reset. If None, resets all clients.
        """
        with self.lock:
            if client_id:
                self.requests[client_id] = []
            else:
                self.requests.clear()
            self.concurrent_requests = 0

# Create global rate limiter instance
rate_limiter = RateLimiter() 