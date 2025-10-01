#!/usr/bin/env python3
import os, time, base64, json
from urllib.parse import urlparse
from jwcrypto import jwk
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from playwright.sync_api import sync_playwright

# --- config (env-friendly)
PRIVATE_KEY_PEM = os.getenv("JWKS_PRIVATE_KEY_PEM", "private-key.pem")
PUBLIC_JWK_FILE   = os.getenv("PUBLIC_JWK_FILE", "public-key.jwk")
SIGNATURE_AGENT   = os.getenv("SIGNATURE_AGENT_URL",
                             "https://jwks.bluemesh.dpdns.org/.well-known/http-message-signatures-directory")
USER_AGENT        = os.getenv("SCRAPER_USER_AGENT", "MyVerifiedBot/1.0 (+mailto:you@yourdomain.com)")
SIGN_EXPIRY       = int(os.getenv("SIGN_EXPIRY_SECONDS", "60"))

# --- helpers
def b64url_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected Ed25519 private key")
    return key

def compute_keyid_from_jwk(path: str) -> str:
    with open(path, "r") as f:
        jwk_json = json.load(f)
    # jwcrypto expects a single JWK or JWKSet; create JWK and thumbprint
    j = jwk.JWK(**{k: jwk_json["kty"] and jwk_json.get("kty")}) if False else None
    # simpler: read the first key object and construct JWK
    k = jwk_json if "kty" in jwk_json else jwk_json["keys"][0]
    jwk_obj = jwk.JWK(**{kname: k[kname] for kname in ("kty", "crv", "x")})
    return b64url_no_pad(jwk_obj.thumbprint().encode())

# --- build signature headers for a request
def build_signature_headers(url: str, method: str, privkey: Ed25519PrivateKey, keyid: str, covered_components=None):
    parsed = urlparse(url)
    authority = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    method = method.upper()
    covered_components = covered_components or ["@method", "@authority", "@path", "signature-agent"]
    created = int(time.time())
    expires = created + SIGN_EXPIRY
    nonce = b64url_no_pad(os.urandom(32))

    # Create signing string (exact order same as components)
    lines = []
    for comp in covered_components:
        if comp == "@method":
            lines.append(f"@method: {method}")
        elif comp == "@authority":
            lines.append(f"@authority: {authority}")
        elif comp == "@path":
            lines.append(f"@path: {path}")
        elif comp == "signature-agent":
            lines.append(f"signature-agent: {SIGNATURE_AGENT}")
        else:
            raise ValueError("unsupported component: " + comp)
    signing_string = "\n".join(lines) + "\n"

    sig = privkey.sign(signing_string.encode("utf-8"))
    sig_b64 = b64url_no_pad(sig)

    comps_str = " ".join(f'"{c}"' for c in covered_components)
    sig_input = (f'sig1=({comps_str});created={created};expires={expires};'
                 f'keyid="{keyid}";alg="ed25519";nonce="{nonce}";tag="web-bot-auth"')
    signature = f"sig1=:{sig_b64}:"

    # Signature-Agent must be a quoted https URL (structured field)
    return {
        "Signature-Input": sig_input,
        "Signature": signature,
        "Signature-Agent": f'"{SIGNATURE_AGENT}"',
        "User-Agent": USER_AGENT
    }

# --- main fetch using Playwright & request interception
def fetch_with_playwright(url: str, privkey, keyid, headless=True, timeout=60_000):
    headers_to_attach = build_signature_headers(url, "GET", privkey, keyid)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, args=["--no-sandbox"])
        context = browser.new_context(user_agent=USER_AGENT)

        def route_handler(route, request):
            # Attach our headers to every outgoing request (initial + resources)
            new_headers = dict(request.headers)
            # Merge - do not overwrite important browser headers
            for k, v in headers_to_attach.items():
                new_headers[k] = v
            route.continue_(headers=new_headers)

        context.route("**/*", route_handler)
        page = context.new_page()
        page.goto(url, timeout=timeout, wait_until="networkidle")
        html = page.content()
        status = page.evaluate("() => document.readyState")  # quick check
        context.close()
        browser.close()
        return html

# --- usage
if __name__ == "__main__":
    priv = load_private_key(PRIVATE_KEY_PEM)
    keyid = compute_keyid_from_jwk(PUBLIC_JWK_FILE)
    test_url = "https://example.com/"  # replace with allowed target
    html = fetch_with_playwright(test_url, priv, keyid)
    print("fetched length:", len(html))
