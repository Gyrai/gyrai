FROM python:3.12-slim
WORKDIR /gw
COPY gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY collectors/aicp_collectors /gw/aicp_collectors
COPY gateway/gw /gw/gw
COPY gateway/mock_upstream.py /gw/mock_upstream.py
RUN useradd -r -u 10003 aicp && chown -R aicp /gw
USER aicp
EXPOSE 8080
CMD ["uvicorn", "gw.main:app", "--host", "0.0.0.0", "--port", "8080"]
