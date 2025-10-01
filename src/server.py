
# #!/usr/bin/env python3
# from flask import Flask, jsonify, make_response, request
# import json, time, os, base64, logging
# from jwcrypto import jwk
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# app = Flask(__name__)
# logging.basicConfig(level=logging.INFO)

# # Load JWKS
# with open("jwks.json", "r") as f:
#     JWKS = json.load(f)

# # Load private key
# with open("private-key.pem", "rb") as f:
#     private_key = serialization.load_pem_private_key(f.read(), password=None)
#     if not isinstance(private_key, Ed25519PrivateKey):
#         raise RuntimeError("Expecting Ed25519 private key")

# def b64url_no_pad(b: bytes) -> str:
#     return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

# @app.route("/.well-known/http-message-signatures-directory")
# def jwks_directory():
#     now = int(time.time())
#     expires = now + 60
#     key = JWKS["keys"][0]

#     jwk_obj = jwk.JWK(**{k: key[k] for k in ("kty", "crv", "x")})
#     keyid = b64url_no_pad(jwk_obj.thumbprint().encode())
#     signing_input_label = "sig1"
#     nonce = b64url_no_pad(os.urandom(32))

#     sig_input = (
#         f'{signing_input_label}=("@authority");'
#         f'alg="ed25519";'
#         f'keyid="{keyid}";'
#         f'nonce="{nonce}";'
#         f'tag="http-message-signatures-directory";'
#         f'created={now};'
#         f'expires={expires}'
#     )

#     signing_string = f"@authority: {request.host}\n"
#     sig_bytes = private_key.sign(signing_string.encode("utf-8"))
#     sig_b64 = b64url_no_pad(sig_bytes)
#     signature_header = f'{signing_input_label}=:{sig_b64}:'

#     resp = make_response(json.dumps(JWKS), 200)
#     resp.headers["Content-Type"] = "application/http-message-signatures-directory+json"
#     resp.headers["Signature-Input"] = sig_input
#     resp.headers["Signature"] = signature_header
#     resp.headers["Cache-Control"] = "max-age=86400"
#     return resp

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=8000)



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
