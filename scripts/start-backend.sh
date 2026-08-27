#!/bin/bash
export PATH="/Users/ew/.pyenv/versions/3.13.13/bin:/usr/local/bin:/usr/bin:/bin"
cd /Users/ew/Downloads/productD/ai-orchestrator/backend
exec /Users/ew/.pyenv/versions/3.13.13/bin/uvicorn main:app --host 0.0.0.0 --port 8000
