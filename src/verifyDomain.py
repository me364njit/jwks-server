import requests

jwks_url = "https://jwks.bluemesh.dpdns.org/.well-known/http-message-signatures-directory"
resp = requests.get(jwks_url)
jwks = resp.json()
print(jwks)
