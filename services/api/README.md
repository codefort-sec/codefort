# CodeFort API Service

FastAPI backend orchestrating pull-request security scans, policy evaluation, and GitHub/Extension integrations.

## Development

```bash
# Set up environment
uv venv
source .venv/bin/activate

# Install dependencies
uv pip install -e ".[dev]"

# Run API server
uvicorn app.main:app --reload --port 8000
```
