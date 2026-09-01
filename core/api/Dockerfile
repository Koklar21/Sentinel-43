FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

RUN groupadd --gid 65532 s43 \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin s43 \
    && mkdir -p /app/logs /app/sentinel43_state \
    && chown -R 65532:65532 /app/logs /app/sentinel43_state
USER 65532:65532

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "core.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
