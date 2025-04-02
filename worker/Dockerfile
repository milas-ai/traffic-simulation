FROM --platform=linux/amd64 python:3 AS build

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update --allow-insecure-repositories && apt-get install -y --allow-unauthenticated \
    ca-certificates \
    iperf3 \
    netwox

COPY ./src ./src

ENTRYPOINT ["python", "./src/main.py"]