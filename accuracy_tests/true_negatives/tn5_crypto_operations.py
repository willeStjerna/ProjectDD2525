
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
