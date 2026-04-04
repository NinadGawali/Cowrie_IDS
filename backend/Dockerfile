# Backend Dockerfile for Honeypot Analyzer
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Workdir
WORKDIR /app

# Install dependencies first (better layer caching)
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy backend and frontend (compose build context is repo root)
COPY backend /app/backend
COPY frontend /app/frontend
COPY model_training /app/model_training

# Default environment
ENV LOG_DIR=/app/cowrie_logs
ENV MODEL_PATH=/app/model_training/model.pkl
EXPOSE 5000

# Start Flask app
CMD ["python", "-m", "backend.app"]
