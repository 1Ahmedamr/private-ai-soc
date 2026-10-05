FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "scripts.run_watch_ingest"]
