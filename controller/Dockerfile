FROM python:3 AS build

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt
RUN DEBIAN_FRONTEND=noninteractive apt-get update --allow-insecure-repositories && \
    apt-get install -y --allow-unauthenticated \
    tshark

COPY ./src ./src

ENTRYPOINT ["python", "./src/main.py"]