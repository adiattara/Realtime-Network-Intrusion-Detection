FROM python:3.10-slim

WORKDIR /app

COPY . /app

RUN pip install --upgrade pip && pip install -r requirements.txt

CMD ["python", "Kafa_ingestion/producer.py", "-i", "eth0", "-b", "kafka:9092"]
