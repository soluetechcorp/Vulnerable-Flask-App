FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

WORKDIR /apps/

RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

EXPOSE 5050

# Add a HEALTHCHECK so orchestration platforms can verify container liveness.
# Security: ensures the container is serving the application and can be marked unhealthy if not.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD curl -fsS http://127.0.0.1:5050/ || exit 1

ENTRYPOINT ["python"]

CMD ["app.py"]