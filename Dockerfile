FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

WORKDIR /apps/

RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

EXPOSE 5050

# Healthcheck to ensure container is serving the app; uses a lightweight Python check.
# Security: helps orchestration detect unhealthy instances and avoid sending traffic to them (fixes CKV_DOCKER_2).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import sys, urllib2; resp=urllib2.urlopen('http://127.0.0.1:5050'); sys.exit(0 if resp.getcode()==200 else 1)"

ENTRYPOINT ["python"]

CMD ["app.py"]