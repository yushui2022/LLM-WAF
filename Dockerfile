FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY . .
RUN pip install --no-cache-dir .

EXPOSE 8080

CMD ["llm-waf", "--host", "0.0.0.0", "--port", "8080"]
