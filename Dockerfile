FROM python:3.12-slim

WORKDIR /cbac

# Install dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/        ./app/
COPY static/     ./static/
COPY dashboard.html .

# .env is NOT copied — inject secrets via environment variables at runtime:
#   docker run -e JWT_SECRET=... -e DB_PATH=/data/cbac.db ...

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
