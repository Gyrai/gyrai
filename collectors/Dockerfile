FROM python:3.12-slim
WORKDIR /collectors
COPY collectors/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY collectors/aicp_collectors ./aicp_collectors
COPY samples /samples
RUN useradd -r -u 10002 aicp && mkdir -p /state && chown aicp /state
USER aicp
ENV HOME=/state
ENTRYPOINT ["python", "-m", "aicp_collectors.run"]
