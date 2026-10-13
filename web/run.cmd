@echo off
rem Запуск веб-приложения на Windows.
rem Открыть потом:  http://127.0.0.1:8000
rem
rem PYTHONUTF8=1 обязателен: консоль Windows по умолчанию не UTF-8,
rem и кириллица в сообщениях ронит процесс.

cd /d "%~dp0"
set PYTHONUTF8=1

rem Для разработки раскомментируйте — 2048-битный ключ вместо 32768-битного,
rem RSA-операции станут мгновенными вместо 16 секунд:
rem set RSA_KEY_PREFIX=%~dp0..\ЗИ_ЛР\key_dev

if not exist .venv\Scripts\python.exe (
    echo Нет виртуального окружения. Создайте его:
    echo     python -m venv .venv
    echo     .venv\Scripts\pip install -r requirements.txt
    exit /b 1
)

.venv\Scripts\python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
