FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py schema.sql ./
RUN useradd -u 10001 app
USER app
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
