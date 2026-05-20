# treasure-hunt

## 1. Summary

- **Category**: Web
- **Points**: 100
- **Solves**: 645

### Description

> `Let's go hunt down some treasure! The flag is split into 4 parts. I'll give you the first one right here: tjctf`

## 2. Analysis

### Vulnerability

The challenge requires finding four separate parts of the flag and combining them.

The first part is given directly in the description:

```text
tjctf
```

Visiting the main page reveals the second part hidden in the HTML:

```sh
curl https://treasure-hunt.tjc.tf/
```

```html
<p hidden>_and_</p>
```

So the second discovered part is:

```text
_and_
```

The page also contains a form that sends a `POST` request:

```html
<form method="POST">
  <input type="submit" value="Learn More" />
</form>
```

Sending a `POST` request gives a redirect response with a cookie:

```sh
curl -X POST -i https://treasure-hunt.tjc.tf/
```

```text
HTTP/2 302
location: /extra_info
set-cookie: silver_coffer={s1lv3r; Path=/
```

The cookie contains another part of the flag:

```text
{s1lv3r
```

Next, checking `robots.txt` reveals a hidden path:

```sh
curl https://treasure-hunt.tjc.tf/robots.txt
```

```text
User-agent: *
Disallow: /gold-coffer
Allow: /
```

Requesting `/gold-coffer` returns the final part:

```sh
curl https://treasure-hunt.tjc.tf/gold-coffer
```

```text
g0ld}
```

## 3. Exploit Flow

1. **Read the Challenge Description**

   The first part is provided directly:

   ```text
   tjctf
   ```

1. **Inspect the Main Page HTML**

   ```html
   <p hidden>_and_</p>
   ```

   This gives:

   ```text
   _and_
   ```

1. **Send a POST Request**

   ```sh
   curl -X POST -i https://treasure-hunt.tjc.tf/
   ```

   The `Set-Cookie` header contains:

   ```text
   {s1lv3r
   ```

1. **Check `robots.txt`**

   ```sh
   curl https://treasure-hunt.tjc.tf/robots.txt
   ```

   This reveals `/gold-coffer`, which returns:

   ```text
   g0ld}
   ```

   Combining the parts gives the final flag.

## 4. Flag

`tjctf{s1lv3r_and_g0ld}`
