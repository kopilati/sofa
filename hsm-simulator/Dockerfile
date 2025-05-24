FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY hsm_service.py .

EXPOSE 8080

CMD ["python", "hsm_service.py"] 