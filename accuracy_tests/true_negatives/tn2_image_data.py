
import base64

# Small PNG image data (1x1 transparent pixel)
IMAGE_DATA = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="

def get_default_avatar():
    """Return default avatar image as bytes"""
    return base64.b64decode(IMAGE_DATA)

def save_image(filename):
    """Save default image to file"""
    with open(filename, 'wb') as f:
        f.write(get_default_avatar())
