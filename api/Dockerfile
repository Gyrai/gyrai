FROM python:3.12-slim
# TODO before customer ship: switch to a FIPS/STIG base (Iron Bank python or Chainguard) and run as non-root.
WORKDIR /app
COPY api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY schemas /schemas
COPY evidence /evidence
COPY api/app /app/app
RUN useradd -r -u 10001 aicp && chown -R aicp /app
USER aicp
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
