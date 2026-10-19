FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SERVICE_NAME=rag-assistant
WORKDIR /srv
COPY rag-assistant/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY _shared/resilience_common.py ./
COPY rag-assistant/rag.py ./
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "rag:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--timeout-graceful-shutdown", "3"]
