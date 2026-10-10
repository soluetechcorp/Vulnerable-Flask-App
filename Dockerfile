FROM python:2.7.14-jessie

WORKDIR /apps/

COPY app/ /apps/

WORKDIR /apps/

RUN pip install -U pip setuptools && pip install -r /apps/requirements.txt

# Create a dedicated non-root user and ensure app files are owned by that user.
# Security: Avoid running containers as root to reduce impact of a container escape (CWE-1032).
RUN useradd -m -s /bin/bash appuser && chown -R appuser:appuser /apps/

# Switch to the non-root user for following instructions and runtime.
USER appuser

EXPOSE 5050

ENTRYPOINT ["python"]

CMD ["app.py"]
