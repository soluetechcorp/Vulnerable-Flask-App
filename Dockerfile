FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

WORKDIR /apps/

RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

EXPOSE 5050

# Add a lightweight healthcheck to allow orchestrators to detect unhealthy containers
# Security/operational comment: Healthcheck ensures the container runtime can detect and restart
# unhealthy instances (CWE-1032).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:5050/health || exit 1

ENTRYPOINT ["python"]

CMD ["app.py"]