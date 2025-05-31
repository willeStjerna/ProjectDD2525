#!/usr/bin/env python3
"""
Test samples for the Encoded Script Detection Tool
This file contains examples of encoded malicious content for testing
"""

# Example 1: Base64 encoded system command
# This decodes to: os.system('rm -rf /')
malicious_b64 = "b3Muc3lzdGVtKCdybSAtcmYgLycpCg=="

# Example 2: Hex encoded network request
# This decodes to: import urllib.request; urllib.request.urlopen('http://evil.com')
malicious_hex = "\\x69\\x6d\\x70\\x6f\\x72\\x74\\x20\\x75\\x72\\x6c\\x6c\\x69\\x62\\x2e\\x72\\x65\\x71\\x75\\x65\\x73\\x74\\x3b\\x20\\x75\\x72\\x6c\\x6c\\x69\\x62\\x2e\\x72\\x65\\x71\\x75\\x65\\x73\\x74\\x2e\\x75\\x72\\x6c\\x6f\\x70\\x65\\x6e\\x28\\x27\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x65\\x76\\x69\\x6c\\x2e\\x63\\x6f\\x6d\\x27\\x29"

# Example 3: URL encoded eval statement
# This decodes to: eval(compile('malicious code', '<string>', 'exec'))
malicious_url = "eval%28compile%28%27malicious%20code%27%2C%20%27%3Cstring%3E%27%2C%20%27exec%27%29%29"

# Example 4: Benign Base64 (should not trigger high risk)
benign_b64 = "SGVsbG8gV29ybGQ="  # "Hello World"

def create_test_files():
    """Create test files with various encoded content"""
    
    # Malicious test file
    with open('test_malicious.py', 'w') as f:
        f.write(f'''#!/usr/bin/env python3
"""
Test file with malicious encoded content
"""

import base64
import os

# This looks innocent but contains malicious Base64
encoded_payload = "{malicious_b64}"
decoded = base64.b64decode(encoded_payload).decode()

# Another suspicious pattern with hex encoding
hex_command = "{malicious_hex}"

# URL encoded suspicious content
url_encoded = "{malicious_url}"

# Some legitimate code
def legitimate_function():
    return "This is normal"
''')
    
    # Benign test file
    with open('test_benign.py', 'w') as f:
        f.write(f'''#!/usr/bin/env python3
"""
Test file with benign encoded content
"""

import base64

# This is just a greeting
greeting = "{benign_b64}"
decoded_greeting = base64.b64decode(greeting).decode()

# Normal hex values (not suspicious)
hex_data = "48656c6c6f"  # "Hello"

def normal_function():
    print("This is a normal function")
    return True
''')
    
    print("Created test files: test_malicious.py and test_benign.py")

if __name__ == "__main__":
    create_test_files()