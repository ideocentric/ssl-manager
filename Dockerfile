FROM python:3.13-slim

# Install openssl for P7B generation
RUN apt-get update && apt-get install -y --no-install-recommends openssl gcc python3-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Persist the SQLite database via a volume
VOLUME ["/app/instance"]

EXPOSE 5001

CMD ["python", "app.py"]
