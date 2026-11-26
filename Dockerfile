FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN mkdir -p /app/data /app/uploads

ENV HOST=0.0.0.0
ENV PORT=8080
ENV DB_PATH=/app/data/portfolio.db
ENV UPLOAD_DIR=/app/uploads

EXPOSE 8080

CMD ["python3", "server.py"]
