FROM python:3.9
LABEL maintainer="tanks2438@outlook.kr"

COPY . /app/chat

WORKDIR /app/chat

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "server.py"]