
import base64
import json

# Store configuration in Base64 for obfuscation from casual viewing
CONFIG_DATA = "eyJkYXRhYmFzZV91cmwiOiAicG9zdGdyZXM6Ly9sb2NhbGhvc3Q6NTQzMi9teWRiIiwgImRlYnVnIjogZmFsc2V9"

def load_config():
    """Load application configuration"""
    return json.loads(base64.b64decode(CONFIG_DATA).decode())

def get_database_url():
    config = load_config()
    return config['database_url']
