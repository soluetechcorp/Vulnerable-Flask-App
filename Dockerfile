FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

WORKDIR /apps/

RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

EXPOSE 5050

# Security: Add a HEALTHCHECK so orchestrators and registries can determine container health (CWE-1032)
# Use a lightweight TCP connect test to avoid adding extra runtime dependencies like curl/wget
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD python -c "import socket,sys; s=socket.socket(); s.settimeout(2);
try: s.connect(('127.0.0.1',5050)); s.close(); sys.exit(0)
except Exception as e: sys.exit(1)"

ENTRYPOINT ["python"]

CMD ["app.py"]