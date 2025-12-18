FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY . /app
COPY files /app/files
COPY manifests /app/manifests
COPY clean-logo.png /app/clean-logo.png


# Install system deps
RUN apt-get update && \
    apt-get install -y ffmpeg curl unzip && \
    rm -rf /var/lib/apt/lists/*

# Install c2patool binary (Linux x64)
RUN apt-get update && apt-get install -y curl tar \
    && curl -fSL -o /tmp/c2patool.tar.gz https://github.com/contentauth/c2patool/releases/download/v0.9.12/c2patool-v0.9.12-x86_64-unknown-linux-gnu.tar.gz \
    && tar -xzf /tmp/c2patool.tar.gz -C /usr/local/bin --strip-components=1 \
    && chmod +x /usr/local/bin/c2patool \
    && rm /tmp/c2patool.tar.gz


# Python deps
RUN pip install --upgrade pip
#RUN pip install c2pa-python
RUN pip install -r requirements.txt

# Start the server
ENTRYPOINT uvicorn app:app --host 0.0.0.0 --port 8000 --timeout-keep-alive 100000 --workers 2
