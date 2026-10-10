FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

WORKDIR /apps/

RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

EXPOSE 5050

# Add a HEALTHCHECK so orchestrators can detect unhealthy containers (prevents silent failures, CWE-1032)
# Uses python (present in the base image) to attempt to connect to the local HTTP port.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import socket,sys; s=socket.socket(); s.settimeout(2); \ 
try:\n  s.connect(('127.0.0.1',5050)); sys.exit(0)\nexcept:\n  sys.exit(1)"

ENTRYPOINT ["python"]

CMD ["app.py"]
