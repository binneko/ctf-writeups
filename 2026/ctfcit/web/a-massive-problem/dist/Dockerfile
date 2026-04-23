FROM python:3.12-slim
WORKDIR /app
COPY app/ /app/
RUN pip install --no-cache-dir -r requirements.txt
ENV FLASK_APP=app.py
ENV FLAG=CIT{test_flag}
RUN mkdir -p /app/instance
EXPOSE 5000
CMD ["python", "app.py"]
