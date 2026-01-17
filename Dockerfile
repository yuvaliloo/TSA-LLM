# Use Python 3.11 slim as the base
FROM python:3.11-slim

# Install system dependencies for building llama-cpp and structural analysis
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libopenblas-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy only requirements first to leverage Docker layer caching
COPY ./requirements.txt .

# Install dependencies
# Note: This will compile llama-cpp-python for the container's Linux environment
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code and model metadata
# We do NOT copy 'venv311' or the large .gguf file into the image
COPY ./src/ ./src/
COPY ./models/sfem_model.pkl ./models/
COPY ./models/meta_weigher.pkl ./models/
COPY ./src/templates/ ./templates/
# Create a mount point for the large LLM model and RAG memory
RUN mkdir -p /app/external_models /app/src/sentinel_memory

# Expose the port for your EnsembleServer/API
EXPOSE 5000

# Set environment variables for the paths inside the container
ENV MODEL_PATH=/app/external_models/Phi-3-mini-4k-instruct-q4.gguf
ENV PYTHONUNBUFFERED=1

# This keeps the container running and manages your workers
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "300", "EnsemblePipeline:app"]