FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

WORKDIR /apps/

RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

EXPOSE 5050

# Add a Docker HEALTHCHECK so orchestrators can detect unhealthy containers.
# Use the bundled Python to perform a lightweight HTTP check; avoid depending on curl/wget.
# Security: healthcheck runs against localhost to avoid exposing internal interfaces.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib2,sys; r=urllib2.urlopen('http://127.0.0.1:5050/'); sys.exit(0 if r.getcode()==200 else 1)"

ENTRYPOINT ["python"]

CMD ["app.py"]