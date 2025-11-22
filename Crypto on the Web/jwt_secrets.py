import jwt


encoded = jwt.encode({"username": "admin", "admin": True}, key = "secret", algorithm = "HS256")

print(encoded)
