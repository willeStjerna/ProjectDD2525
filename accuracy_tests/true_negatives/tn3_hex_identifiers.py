
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
