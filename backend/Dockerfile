FROM python:3.11-slim-bookworm

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY backend /app/backend
COPY frontend /app/frontend
COPY model_training /app/model_training

ENV LOG_DIR=/app/cowrie_logs
ENV MODEL_PATH=/app/model_training/model.pkl

EXPOSE 5000

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "backend.app:app"]