FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

WORKDIR /apps/

RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

EXPOSE 5050

# Healthcheck added to ensure container orchestration can monitor app liveness.
# Uses python to test TCP connection to localhost:5050. Keeps the image self-contained without adding curl/wget.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import sys,socket; s=socket.socket(); s.settimeout(3);\
try: s.connect(('127.0.0.1',5050)); s.close(); print('OK');\
except: sys.exit(1)"

ENTRYPOINT ["python"]

CMD ["app.py"]