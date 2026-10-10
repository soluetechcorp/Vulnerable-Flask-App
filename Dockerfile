FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

WORKDIR /apps/

RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

EXPOSE 5050

# Add a HEALTHCHECK so container orchestration platforms and scanners can verify the app
# is responding; this helps detect failed instances early (CWE-1032 guidance).
# Security: use a simple HTTP check; if the app exposes a /health endpoint, use that.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 CMD curl -f http://localhost:5050/ || exit 1

ENTRYPOINT ["python"]

CMD ["app.py"]
