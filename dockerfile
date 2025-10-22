FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y wget && \
    wget https://github.com/aquasecurity/trivy/releases/download/v0.45.1/trivy_0.45.1_Linux-64bit.tar.gz && \
    tar -xzf trivy_0.45.1_Linux-64bit.tar.gz && \
    mv trivy /usr/local/bin/ && \
    rm trivy_0.45.1_Linux-64bit.tar.gz && \
    apt-get clean

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY container_scanner.py .

CMD ["python", "container_scanner.py", "--scan"]
