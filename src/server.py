
#!/usr/bin/env python3
from flask import Flask, jsonify, make_response, request
import json, time, os, base64, logging
from jwcrypto import jwk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Load JWKS
with open("jwks.json", "r") as f:
    JWKS = json.load(f)

# Load private key
with open("private-key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RuntimeError("Expecting Ed25519 private key")

def b64url_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

@app.route("/.well-known/http-message-signatures-directory")
def jwks_directory():
    now = int(time.time())
    expires = now + 60
    key = JWKS["keys"][0]

    jwk_obj = jwk.JWK(**{k: key[k] for k in ("kty", "crv", "x")})
    keyid = b64url_no_pad(jwk_obj.thumbprint().encode())
    signing_input_label = "sig1"
    nonce = b64url_no_pad(os.urandom(32))

    sig_input = (
        f'{signing_input_label}=("@authority");'
        f'alg="ed25519";'
        f'keyid="{keyid}";'
        f'nonce="{nonce}";'
        f'tag="http-message-signatures-directory";'
        f'created={now};'
        f'expires={expires}'
    )

    signing_string = f"@authority: {request.host}\n"
    sig_bytes = private_key.sign(signing_string.encode("utf-8"))
    sig_b64 = b64url_no_pad(sig_bytes)
    signature_header = f'{signing_input_label}=:{sig_b64}:'

    resp = make_response(json.dumps(JWKS), 200)
    resp.headers["Content-Type"] = "application/http-message-signatures-directory+json"
    resp.headers["Signature-Input"] = sig_input
    resp.headers["Signature"] = signature_header
    resp.headers["Cache-Control"] = "max-age=86400"
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
