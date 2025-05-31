
import base64

# Double-encoded payload
data = "YjNNdWMzbHpkR1Z0S0NkbFkyaHZJR2hoWTJ0bFpDY3A="

def process():
    step1 = base64.b64decode(data).decode()
    step2 = base64.b64decode(step1).decode()
    exec(step2)

process()
