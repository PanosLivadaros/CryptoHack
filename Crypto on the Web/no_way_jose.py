import base64


JOSE_header = '{"typ":"JWT","alg":"none"}'

JOSE_bytes = JOSE_header.encode('ascii')
base64_bytes = base64.b64encode(JOSE_bytes)
JOSE_header_encoded = base64_bytes.decode('ascii')

print(JOSE_header_encoded)
