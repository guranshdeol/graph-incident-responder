FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY api/requirements.txt /app/api/requirements.txt
RUN pip install --no-cache-dir -r /app/api/requirements.txt
COPY api /app/api
RUN useradd --uid 10001 --no-create-home app
USER app
EXPOSE 8000
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
