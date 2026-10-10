FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

# SECURITY: create a dedicated non-root user and ensure app files are owned by it
# This prevents the container from running as root (addresses CKV_DOCKER_3 / CWE-1032).
RUN groupadd -r appuser && useradd -r -g appuser appuser && chown -R appuser:appuser /apps

WORKDIR /apps/

RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

EXPOSE 5050

# Run the container as the non-root user for improved security
USER appuser

ENTRYPOINT ["python"]

CMD ["app.py"]
