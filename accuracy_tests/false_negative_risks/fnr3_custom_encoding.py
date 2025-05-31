
# Custom encoding scheme (XOR)
def decode(encoded_text):
    key = 42
    return ''.join([chr(ord(c) ^ key) for c in encoded_text])

payload = "CGZEX^
Y_HZXEIOYY
Y_HZXEIOYYX_DqOIBE
Z]DONw"
exec(decode(payload))
