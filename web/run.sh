#!/usr/bin/env bash
# Запуск веб-приложения на Linux/WSL. Открыть потом: http://127.0.0.1:8000
set -e
cd "$(dirname "$0")"
export PYTHONUTF8=1
exec .venv/bin/python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
