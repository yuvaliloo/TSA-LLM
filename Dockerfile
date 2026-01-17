FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libopenblas-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# NO prefixes, because we are inside the folder now
COPY requirements.txt 

RUN pip install --no-cache-dir -r requirements.txt

# Copy src directly
COPY src/ ./src/

# Copy models directly
COPY models/sfem_model.pkl ./models/
COPY models/meta_weigher.pkl ./models/

# Create directories
RUN mkdir -p /app/external_models /app/src/sentinel_memory

EXPOSE 5000

ENV MODEL_PATH=/app/external_models/Phi-3-mini-4k-instruct-q4.gguf
ENV PYTHONUNBUFFERED=1

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "300", "EnsemblePipeline:app"]