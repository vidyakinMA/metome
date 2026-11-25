FROM python:3.12-slim

WORKDIR /app

# зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# код мессенджера
COPY server.py .
COPY client.html .
COPY notification.mp3 .

# данные БД в постоянном томе (Railway volume)
ENV CLOUD=1
ENV PORT=8080

EXPOSE 8080

CMD ["python", "server.py"]