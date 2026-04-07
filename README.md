# GuardRail

Minimal Phase A scaffold for a software supply chain security demo using FastAPI.

## Quickstart

```bash
make up-registry
make up-app
curl localhost:8000/health
curl localhost:8000/hello
make down
```

## Services

- App: `http://localhost:8000`
- Local registry: `http://localhost:5000`
