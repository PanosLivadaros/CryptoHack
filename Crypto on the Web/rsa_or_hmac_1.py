import requests
import jwt_patched as jwt


URL = "http://web.cryptohack.org/rsa-or-hmac/"


def api(path: str):
    """Small helper to call any challenge endpoint."""
    return requests.get(URL + path).json()


pub_key = api("get_pubkey/")["pubkey"]

evil_token = jwt.encode(
    {"username": "user", "admin": True},
    pub_key,
    algorithm="HS256"
)

print("Evil token:", evil_token)

response = api(f"authorise/{evil_token}/")
print(response)
