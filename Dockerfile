FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

WORKDIR /apps/

RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

EXPOSE 5050

# Security: add HEALTHCHECK to allow orchestrators to detect unhealthy containers
# The check uses HTTP to verify the application is responding on the expected port.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5050/ || exit 1

ENTRYPOINT ["python"]

CMD ["app.py"]
