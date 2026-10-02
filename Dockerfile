FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY scripts/warm_tiktoken.py ./scripts/warm_tiktoken.py
COPY slice/ ./slice/
COPY samples/ ./samples/
COPY main.py ./main.py

# Cache tiktoken's vocabulary in the image so token counting works offline.
# A failed download (offline build) does not fail the build; counts then use an estimate.
RUN python scripts/warm_tiktoken.py || echo "tiktoken warm-up skipped: token counts will use the chars/4 estimate"

# Persist config.yaml and history.json in /data (mounted from the host)
ENV SLICE_CONFIG=/data/config.yaml \
    SLICE_HISTORY=/data/history.json
RUN mkdir -p /data

EXPOSE 7654

# Bind to 0.0.0.0 so the app is reachable from outside the container
CMD ["python", "-m", "slice", "serve", "--host", "0.0.0.0", "--port", "7654"]
