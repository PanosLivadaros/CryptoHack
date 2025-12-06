import requests
import json


url_sign = "https://web.cryptohack.org/digestive/sign/"
url_verify = "https://web.cryptohack.org/digestive/verify/"

username = "admin"
r = requests.get(url_sign + username)

response = json.loads(r.text)

msg = '{"admin": false, "username": "admin", "admin": true}'
signature = response['signature']

r = requests.get(url_verify + msg + "/" + signature)
print(r.text)
