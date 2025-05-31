
import base64

# Payload split across variables
part_a = "b3Muc3lzdGVtKCdtYWxp"
part_b = "Y2lvdXMgY29tbWFuZCcp"

def execute():
    full_payload = base64.b64decode(part_a).decode() + base64.b64decode(part_b).decode()
    exec(full_payload)

execute()
