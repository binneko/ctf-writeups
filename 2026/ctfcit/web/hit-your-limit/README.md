# Hit Your Limit (Upsolved)

## 1. Summary

- **Category**: Web

### Description

> `A wise man once said, stay calm, cool and collected. Don't go above your limit.`

## 2. Analysis

### Vulnerability

- **Rate Limit Bypass via Trailing Slash**: The application implements a rate limiter on the `/api/flag` endpoint. However, the middleware responsible for rate limiting fails to normalize the URL path, allowing an attacker to bypass the restriction by adding a trailing slash (e.g., `/api/flag/`).

## 3. Exploit Flow

1. **Identifying the Constraint**
   The endpoint `/api/flag?guess=` allows for character-by-character brute-forcing, but it is strictly limited to 5 requests every 5 minutes.

   ```bash
   $ curl 'http://23.179.17.92:5559/api/flag?guess=CIT\{B'
   {"error":"Rate limit exceeded","limit":5,"message":"Too many requests. Retry in 270s.","requests":6}
   ```

2. **Bypassing the Middleware**
   By appending a `/` to the endpoint, the rate-limiting middleware (likely matching exact strings) treats it as a different path and fails to trigger. Meanwhile, the back-end server treats `/api/flag` and `/api/flag/` as the same resource, allowing infinite guesses.

   ```bash
   $ curl 'http://23.179.17.92:5559/api/flag/?guess=CIT\{R'
   {"result":"correct"}
   ```

## 4. Conclusion

This challenge demonstrates a classic **Path Normalization** discrepancy between a middleware and the application server. While the rate limiter was configured for a specific path, adding a trailing slash was sufficient to circumvent the security policy. It highlights the importance of consistent URL handling across all layers of a web stack.
