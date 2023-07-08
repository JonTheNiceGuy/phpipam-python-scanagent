# Use an official Python runtime as the base image
FROM python:3.9-slim
LABEL org.opencontainers.image.authors="Jon Spriggs <jon@sprig.gs>"
LABEL org.opencontainers.image.source=https://github.com/JonTheNiceGuy/phpipam-python-scanagent
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.description="A network scan agent for PHP-IPAM"

ENV IPAM_SERVER="" \
    IPAM_API_CLIENT="" \
    IPAM_API_TOKEN="" \
    IPAM_API_AGENT_CODE="" \
    IPAM_SLEEP_DURATION="5m" \
    IPAM_MIN_TIME_BETWEEN_SCANS="1h" \
    IPAM_ALWAYS_UPDATE=1 \
    IPAM_REMOVE_OLD_HOSTS=1 \
    IPAM_REMOVE_OLD_HOST_DELAY="48h" \
    LOG_LEVEL="INFO"

WORKDIR /app
COPY nmap_scan/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt update && apt install -y nmap
COPY nmap_scan/nmap_scan.py .

# Set the command to run your script when the container starts
CMD ["python", "nmap_scan.py"]