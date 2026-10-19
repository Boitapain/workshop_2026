FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir httpx==0.28.1
COPY traffic.py /srv/traffic.py
USER 10001:10001
CMD ["python", "/srv/traffic.py"]
