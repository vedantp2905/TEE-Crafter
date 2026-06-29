# Hello HTTP — minimal FastAPI service

A tiny JSON API you can run locally or deploy as a confidential container.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/`, `/health` | no | Liveness + `.env` injection proof |
| GET | `/time` | no | Current UTC timestamp |
| POST | `/echo` | optional Bearer | Echo JSON body back |

When `API_TOKEN` is set in `.env`, `POST /echo` requires
`Authorization: Bearer <API_TOKEN>`.

## Run locally

```bash
cd examples/hello_http
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/time
curl -X POST http://127.0.0.1:8080/echo -H 'Content-Type: application/json' -d '{"hello":"world"}'
```

## Deploy to a TEE

```bash
tee-crafter internal bake-ami --tee-platform snp-aws --region us-east-1

tee-crafter deploy \
  --source ./examples/hello_http \
  --tee-platform snp-aws \
  --ami-id <IMAGE_ID> \
  --secrets-env ./examples/hello_http/.env \
  --persistent \
  --deploy --auto-approve --teardown
```

Interactive API docs are at `/docs` when you hit the service directly (e.g.
locally). Through the attested proxy, use the same paths on your RA-TLS
endpoint.
