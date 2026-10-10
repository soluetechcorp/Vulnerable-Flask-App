FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

WORKDIR /apps/

RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

EXPOSE 5050

# Add a HEALTHCHECK so orchestrators can monitor container health (CWE-1032).
# The healthcheck will attempt to hit the application endpoint; adjust if you add a proper /health route.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5050/ || exit 1

ENTRYPOINT ["python"]

CMD ["app.py"]
