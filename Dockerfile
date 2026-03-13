FROM python:3.13-slim

# Install openssl for P7B generation
# tzdata is required for the TZ environment variable to work correctly in Python
# and SQLite. DEBIAN_FRONTEND suppresses the interactive timezone prompt.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl gcc python3-dev sqlite3 tzdata \
    && rm -rf /var/lib/apt/lists/*
ENV DEBIAN_FRONTEND=

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY wsgi.py .
COPY app/ app/
COPY backup.sh .

# Persist the SQLite database via a volume
VOLUME ["/app/instance"]

EXPOSE 5001

CMD ["python", "wsgi.py"]
