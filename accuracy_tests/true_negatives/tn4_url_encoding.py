
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
