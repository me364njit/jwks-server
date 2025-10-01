from flask import Flask, jsonify, Response, request
import json
import time
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Load your private key once
with open("private-key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Your JWKS JSON
JWKS = {
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

def sign_message(message: bytes) -> str:
    """Sign a message with Ed25519 and return base64 URL-safe encoded string"""
    signature = private_key.sign(message)
    return base64.urlsafe_b64encode(signature).decode().rstrip("=")

@app.route("/.well-known/http-message-signatures-directory")
def serve_jwks():
    # Dynamic timestamps
    created = int(time.time())
    expires = created + 60  # valid for 1 minute

    # Construct Signature-Input header
    keyid = JWKS["keys"][0]["kid"]
    authority = request.host
    sig_input = (
        f'sig1=("@authority");alg="ed25519";keyid="{keyid}";'
        f'tag="http-message-signatures-directory";created={created};expires={expires}'
    )

    # Construct the signing string (simplified for @authority only)
    signing_string = f'@authority: {authority}'.encode()
    signature = sign_message(signing_string)
    sig_header = f'sig1=:{signature}:'

    response = jsonify(JWKS)
    response.headers['Content-Type'] = 'application/http-message-signatures-directory+json'
    response.headers['Signature-Input'] = sig_input
    response.headers['Signature'] = sig_header
    return response

if __name__ == "__main__":
    # For production, serve HTTPS with a real cert
    app.run(host="0.0.0.0", port=5000)
