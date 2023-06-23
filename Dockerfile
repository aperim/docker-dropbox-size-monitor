FROM python:3

LABEL org.opencontainers.image.source=https://github.com/aperim/docker-dropbox-size-monitor
LABEL org.opencontainers.image.description="Dropbox Size Monitor"
LABEL org.opencontainers.image.licenses=UNLICENSED

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app .

CMD ["python", "./monitor.py"]
