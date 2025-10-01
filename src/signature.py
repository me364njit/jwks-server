import json
import time
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes

# ----- Your JWKS -----
jwks = {
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": "N280d3pSdjBfeHBtQVp0bnVydzIyZU5qb0hGTnRaNTlOMkI2Mnc3SzA1TQ",
            "x": "UWdV4AIfsOvEQ7pZRXVdBiTVKhJ5kEWvHL13LAg4u0I"
        }
    ]
}

# ----- Load your private key -----
private_key_pem = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBLGWyLv9Cdz+JxsQ9ktkRzYMXpGuWNre26n0ML9A3Fm
-----END PRIVATE KEY-----"""

private_key = serialization.load_pem_private_key(private_key_pem, password=None)

# ----- Compute Signature -----
# Construct the message to sign: just the @authority component for JWKS
hostname = "jwks.bluemesh.dpdns.org"
message = f"@authority: {hostname}".encode("utf-8")

sig = private_key.sign(message)
sig_b64 = base64.b64encode(sig).decode("utf-8")

# ----- Signature-Input header -----
created = int(time.time())
expires = created + 60  # 1 minute expiry

sig_input = (
    f'sig1=("@authority");alg="ed25519";keyid="{jwks["keys"][0]["kid"]}";'
    f'tag="http-message-signatures-directory";created={created};expires={expires}'
)

# ----- Print ready-to-use headers -----
print("Content-Type: application/http-message-signatures-directory+json")
print(f"Signature-Input: {sig_input}")
print(f"Signature: sig1=:{sig_b64}:")
print("\nJWKS JSON:")
print(json.dumps(jwks, indent=2))
