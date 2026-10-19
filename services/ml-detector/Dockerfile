FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SERVICE_NAME=ml-detector
WORKDIR /srv
COPY ml-detector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && mkdir -p /models /data && chown 10001:10001 /models /data
COPY _shared/resilience_common.py ./
COPY ml-detector/app ./app
COPY ml-detector/train.py ./train.py
USER 10001:10001
WORKDIR /srv/app
ENV PYTHONPATH=/srv
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--timeout-graceful-shutdown", "3"]
