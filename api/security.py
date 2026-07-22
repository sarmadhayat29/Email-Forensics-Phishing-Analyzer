import time
from collections import defaultdict
from fastapi import Request, HTTPException
from typing import Dict, Tuple

class RateLimiter:
    def __init__(self, rate: int, per: int):
        self.rate = rate
        self.per = per
        self.tokens: Dict[str, Tuple[float, float]] = defaultdict(lambda: (self.rate, time.time()))

    def __call__(self, request: Request):
        client_ip = request.client.host if request.client else "unknown"
        
        # In a real app behind a proxy, use X-Forwarded-For:
        # forwarded = request.headers.get("X-Forwarded-For")
        # if forwarded:
        #     client_ip = forwarded.split(",")[0]
            
        now = time.time()
        tokens, last_update = self.tokens[client_ip]
        
        elapsed = now - last_update
        tokens += elapsed * (self.rate / self.per)
        if tokens > self.rate:
            tokens = self.rate
            
        if tokens >= 1:
            self.tokens[client_ip] = (tokens - 1, now)
        else:
            self.tokens[client_ip] = (tokens, now)
            raise HTTPException(status_code=429, detail="Too Many Requests. Please slow down.")

# Max 5 uploads per 60 seconds
upload_limiter = RateLimiter(rate=5, per=60)

# Max 10 login attempts per 60 seconds
login_limiter = RateLimiter(rate=10, per=60)
