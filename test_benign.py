#!/usr/bin/env python3
"""
Test file with benign encoded content
"""

import base64

# This is just a greeting
greeting = "SGVsbG8gV29ybGQ="
decoded_greeting = base64.b64decode(greeting).decode()

# Normal hex values (not suspicious)
hex_data = "48656c6c6f"  # "Hello"

def normal_function():
    print("This is a normal function")
    return True
