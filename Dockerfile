FROM python:3-slim

# Default uid/gid 1000. Delete needs write permission on each file's parent
# directory, so set Compose `user:` to the account that owns the mount.
RUN groupadd --gid 1000 meclean \
    && useradd --uid 1000 --gid 1000 --no-create-home --home-dir /tmp \
        --shell /usr/sbin/nologin meclean

COPY meclean.py /usr/local/bin/meclean.py

USER meclean

ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MECLEAN_ROOT=/data \
    MECLEAN_HOST=0.0.0.0 \
    MECLEAN_PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('MECLEAN_PORT', '8080') + '/health')"

ENTRYPOINT ["python", "/usr/local/bin/meclean.py"]
