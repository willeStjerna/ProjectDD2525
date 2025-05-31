
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
