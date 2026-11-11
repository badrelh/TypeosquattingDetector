# Image with every dnstwist feature: TLSH/ssdeep comparison and pHash screenshots.
# Chromium and its driver are needed by --phash; PIL and Selenium come from requirements-full.txt.
FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium chromium-driver build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt requirements-full.txt ./
RUN pip install --no-cache-dir -r requirements-full.txt

COPY . .

ENTRYPOINT ["python", "-m", "typosquatting"]
CMD ["--help"]
