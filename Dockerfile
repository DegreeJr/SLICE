FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY slice/ ./slice/

# Persist config.yaml and history.json in /data (mounted from the host)
ENV SLICE_CONFIG=/data/config.yaml \
    SLICE_HISTORY=/data/history.json
RUN mkdir -p /data

EXPOSE 7654

# Bind to 0.0.0.0 so the app is reachable from outside the container
CMD ["python", "-m", "slice", "serve", "--host", "0.0.0.0", "--port", "7654"]
