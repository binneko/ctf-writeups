# lactf-invoice-generator

## 1. Summary

- **Category**: Web
- **Points**: 101
- **Solves**: 465

### Description

> `I need an itemized list of everything purchased for LA CTF 2026.`

## 2. Analysis

### Services (docker-compose.yml)

```yml
services:
  invoice-generator:
    build: ./invoice-generator
    ports:
      - "3000:3000"
    networks:
      - app-network
    depends_on:
      - flag

  flag:
    build: ./flag
    networks:
      - app-network
```

The architecture consists of a `flag` server running internally and a PDF generation service accessible via port `3000`.

### Vulnerability

The `generateInvoiceHTML` function constructs an HTML string by directly embedding user-provided values (`name`, `item`, `cost`, `datePurchased`) using template literals without any sanitization or filtering.

```javascript
return `
    <!DOCTYPE html>
    <html>
    ...
      <div class="customer-info">
        <strong>Bill To:</strong>
        ${name}
      </div>
    ...
    </html>
  `;
```

The server uses `puppeteer` to render this HTML and generate a PDF:

```javascript
browser = await puppeteer.launch({
  headless: true,
  args: ["--js-flags=--jitless", "--incognito"],
});

const page = await browser.newPage();
await page.setViewport({ width: 821, height: 1159 });
await page.setContent(invoiceHTML, { waitUntil: "load" });
```

Since the HTML is rendered by a headless browser, an attacker can perform a **Server-Side Request Forgery (SSRF)** attack by injecting an `<iframe>` tag to access the internal `flag` server at `http://flag:8081/flag`.

## 3. Exploit Flow

1. **Crafting the Payload**
   Input an `<iframe>` tag into one of the fields (e.g., `name`) that points to the internal flag service.

   ```python
   json = {
       "name": '<iframe src="http://flag:8081/flag"></iframe>',
       "item": "A",
       "cost": "0",
       "datePurchased": "2026-02-09",
   }
   ```

2. **Execution**
   Send the request to the invoice generator. Puppeteer will render the HTML, resolve the internal request to `http://flag:8081/flag`, and display the content within the iframe in the resulting PDF.

3. **Flag Retrieval**
   Open the generated PDF to view the flag rendered inside the iframe.

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

## 5. Flag

`lactf{plz_s4n1t1z3_y0ur_purch4s3_l1st}`
