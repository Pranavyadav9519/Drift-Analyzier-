# Dockerfile — Sentinel Zero Phishing Detection API
# Builds a lightweight container for the Flask phishing-detection service.

FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code, utilities, pre-trained model, and data
COPY app.py config.py ./
COPY utils/ utils/
COPY models/ models/
COPY data/   data/

# Expose the API port
EXPOSE 5050

# Run the Flask API
CMD ["python", "app.py"]
