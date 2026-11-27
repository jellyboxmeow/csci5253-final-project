FROM python:3.14-trixie
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# RUN python -m grpc_tools.protoc -I./gRPC/proto --python_out=./gRPC --grpc_python_out=./gRPC ./gRPC/proto/gRPC_api.proto
CMD ["python", "-u", "gRPC-server.py"]
