from flask import Flask, render_template_string, request
import re

app = Flask(__name__)

BLOCKED = re.compile(r'__\w+__')

PAGE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Temporary Destruction</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
<div class="vignette"></div>
<div class="grid-bg"></div>

<div class="wrapper">
    <div class="brand">
        <span class="brand-line"></span>
        <h1 class="title" data-text="TEMPORARY DESTRUCTION">TEMPORARY DESTRUCTION</h1>
        <span class="brand-line"></span>
    </div>

    <p class="tagline">something is listening.</p>

    <div class="card">
        <div class="card-bar">
            <div class="bar-dots">
                <i></i><i></i><i></i>
            </div>
        </div>
        <div class="card-inner">
            <form method="POST" action="/" autocomplete="off">
                <div class="field">
                    <textarea
                        name="user_input"
                        id="inp"
                        rows="5"
                        spellcheck="false"
                    >{{ raw_input }}</textarea>
                </div>
                <div class="actions">
                    <button type="submit">
                        <span>TRANSMIT</span>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
                    </button>
                </div>
            </form>
        </div>
    </div>

    {% if output is not none %}
    <div class="response {% if is_error %}bad{% endif %}">
        <div class="card-bar">
            <div class="bar-dots"><i></i><i></i><i></i></div>
        </div>
        <div class="response-inner">
            <pre>{{ output }}</pre>
        </div>
    </div>
    {% endif %}
</div>

<script src="/static/js/main.js"></script>
</body>
</html>'''


@app.route('/', methods=['GET', 'POST'])
def index():
    raw_input = ''
    output = None
    is_error = False

    if request.method == 'POST':
        raw_input = request.form.get('user_input', '')

        if BLOCKED.search(raw_input):
            output = 'rejected.'
            is_error = True
        else:
            try:
                output = render_template_string(raw_input)
            except Exception:
                output = 'error.'
                is_error = True

    return render_template_string(
        PAGE,
        raw_input=raw_input,
        output=output,
        is_error=is_error
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
