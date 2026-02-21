FROM python:3.11-slim

WORKDIR /app

# Cache layer für Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code kopieren
COPY . .

# Security: Non-root User
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["python", "main.py"]