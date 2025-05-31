"""
Mathematical utilities for common calculations
"""

import math

def calculate_area_circle(radius):
    """Calculate the area of a circle"""
    return math.pi * radius ** 2

def calculate_factorial(n):
    """Calculate factorial of a number"""
    if n <= 1:
        return 1
    return n * calculate_factorial(n - 1)

def prime_factors(n):
    """Find prime factors of a number"""
    factors = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1
    if n > 1:
        factors.append(n)
    return factors

# Some Base64 encoded configuration (legitimate)
import base64
CONFIG = base64.b64encode(b'{"precision": 10, "debug": false}').decode()

def get_config():
    """Get configuration settings"""
    return json.loads(base64.b64decode(CONFIG).decode())
