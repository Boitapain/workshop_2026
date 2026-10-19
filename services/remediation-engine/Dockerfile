FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SERVICE_NAME=remediation-engine
WORKDIR /srv
COPY remediation-engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && mkdir -p /data /waf-dynamic && chown 10001:10001 /data /waf-dynamic
COPY _shared/resilience_common.py ./
COPY remediation-engine/app ./app
COPY remediation-engine/policy.yaml ./policy.yaml
COPY remediation-engine/tests ./tests
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--timeout-graceful-shutdown", "3"]
