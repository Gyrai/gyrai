FROM python:3.12-slim
WORKDIR /fwd
COPY forwarder/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY forwarder/fwd ./fwd
RUN useradd -r -u 10004 aicp && mkdir -p /state && chown aicp /state
USER aicp
CMD ["python", "-m", "fwd.main"]
