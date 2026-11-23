# The app, run from a checkout, for looking at it with nothing but Docker
# installed. Start it from the repository's root with: docker compose up app
#
# The image holds Python and the app's dependencies only. The checkout itself
# is mounted read-only at /app when the container starts, so the app that runs
# is the source you are looking at.
FROM python:3.12-slim

# The dependencies come from pyproject.toml, so the pins live in one place.
COPY pyproject.toml /tmp/pyproject.toml
RUN python -c "import tomllib; project = tomllib.load(open('/tmp/pyproject.toml', 'rb'))['project']; print('\n'.join(project['dependencies'] + project['optional-dependencies']['detections']))" > /tmp/requirements.txt \
    && pip install --no-cache-dir --requirement /tmp/requirements.txt \
    && useradd --create-home --uid 1000 bluefire \
    && install -d -o bluefire -g bluefire /workspace

USER bluefire
WORKDIR /app
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "bluefire.cli"]
CMD ["--runs-dir", "/workspace", "ui", "--no-browser"]
