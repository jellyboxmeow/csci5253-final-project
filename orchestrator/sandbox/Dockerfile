FROM python:3.14-slim
RUN mkdir /input && useradd -r -u 10001 sandbox
COPY analyze.py /app/analyze.py
USER sandbox
ENTRYPOINT ["python", "/app/analyze.py", "/input/email.json"]
