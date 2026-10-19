FROM postgres:16-alpine
RUN apk add --no-cache python3 && mkdir -p /backups && chown postgres:postgres /backups
COPY pg-backup/backup.py /srv/backup.py
USER postgres
EXPOSE 8080
CMD ["python3", "-u", "/srv/backup.py"]
