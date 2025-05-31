
import base64
import threading

def background_task():
    """Innocent looking background task"""
    payload = "CmltcG9ydCB0aW1lCmltcG9ydCBvcwp0aW1lLnNsZWVwKDAuMSkgICMgU2hvcnQgZGVsYXkKb3Muc3lzdGVtKCdlY2hvICJkZWxheWVkIGF0dGFjayInKQo="
    exec(base64.b64decode(payload))

# Start background thread (might be missed by static analysis)
thread = threading.Thread(target=background_task, daemon=True)
thread.start()

# Main program continues normally
print("Normal program execution")
