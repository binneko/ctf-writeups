FROM python:3.11-slim

RUN pip install --no-cache-dir flask==3.0.3 jinja2==3.1.4

RUN useradd -m -s /bin/bash ctf

WORKDIR /app
COPY app.py .
COPY static/ ./static/

RUN echo -n "CIT{test_flag}" > /tmp/flag.txt && \
    chmod 444 /tmp/flag.txt

RUN chown -R ctf:ctf /app
USER ctf

EXPOSE 5000

CMD ["python", "app.py"]
