"""
Настройки приложения. Единственное место, где живут пути и параметры.

Всё, что зависит от машины, читается из переменных окружения, чтобы
ничего не приходилось править в коде. Значения по умолчанию рассчитаны
на эту машину (Windows + сборка crypto_cli в WSL).
"""

import os
import secrets
import sys
from pathlib import Path

# Консоль Windows по умолчанию не UTF-8, и обычный print с кириллицей
# роняет процесс с UnicodeEncodeError. Переключаем потоки явно.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

# --------------------------------------------------------------------------
# Пути
# --------------------------------------------------------------------------

WEB_DIR = Path(__file__).resolve().parent          # .../ИБ/web
PROJECT_DIR = WEB_DIR.parent                       # .../ИБ
CRYPTO_DIR = PROJECT_DIR / "ЗИ_ЛР"                 # C++ слой

VAR_DIR = WEB_DIR / "var"                          # рабочие файлы, не в git
DB_PATH = Path(os.environ.get("DB_PATH", VAR_DIR / "app.sqlite3"))
TMP_DIR = VAR_DIR / "tmp"                          # временные файлы для crypto_cli
MAIL_DIR = VAR_DIR / "mail"                        # письма, если SMTP недоступен

# Мастер-ключ лежит ВНЕ каталога веб-приложения: украденная база без него
# не расшифровывается (см. envelope encryption в crypto.py).
SECRETS_DIR = Path(os.environ.get("SECRETS_DIR", PROJECT_DIR / "secrets"))
MASTER_KEY_PATH = SECRETS_DIR / "master.key"

# --------------------------------------------------------------------------
# Криптографический слой
# --------------------------------------------------------------------------

# Путь к исполняемому файлу. На Windows собранного .exe нет (нет g++),
# поэтому по умолчанию берётся Linux-сборка и запускается через WSL.
CRYPTO_CLI = os.environ.get("CRYPTO_CLI", str(CRYPTO_DIR / "crypto_cli"))

# Префикс запуска. Пусто — запускать напрямую (Linux, или свой .exe на Windows).
# "wsl" — прогонять через wsl.exe и переводить пути C:\... в /mnt/c/...
CRYPTO_CLI_LAUNCHER = os.environ.get("CRYPTO_CLI_LAUNCHER", "wsl" if os.name == "nt" else "")
WSL_DISTRO = os.environ.get("WSL_DISTRO", "Ubuntu-22.04")

# Ключ RSA для шифрования и ЭЦП: файлы <префикс>.n, .e, .d
# key_32768 — требование задания. key_dev (2048 бит) быстрее в разработке:
#   set RSA_KEY_PREFIX=...\ЗИ_ЛР\key_dev
RSA_KEY_PREFIX = os.environ.get("RSA_KEY_PREFIX", str(CRYPTO_DIR / "key_32768"))

# --------------------------------------------------------------------------
# Пароли
# --------------------------------------------------------------------------

# Измерено на этой машине: ~6600 итераций Стрибога в секунду.
# 5000 итераций — около 0.8 с на одну проверку пароля. Это обычный
# ориентир для интерактивного входа: пользователь не замечает, а перебор
# дорожает в 5000 раз. Число хранится у каждого пользователя в базе,
# поэтому его можно поднять, не ломая существующие записи.
KDF_ITERATIONS = int(os.environ.get("KDF_ITERATIONS", "5000"))
SALT_BYTES = 16

# --------------------------------------------------------------------------
# Сессии, блокировки, одноразовые коды
# --------------------------------------------------------------------------

SESSION_COOKIE = "session"
SESSION_LIFETIME_SECONDS = 8 * 3600

LOGIN_FLOW_LIFETIME_SECONDS = 10 * 60      # на все три фактора даётся 10 минут
OTP_LIFETIME_SECONDS = 5 * 60              # код из письма живёт 5 минут
OTP_MAX_ATTEMPTS = 5                       # 6 цифр без лимита перебираются мгновенно
RESET_TOKEN_LIFETIME_SECONDS = 30 * 60

MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60

RATE_LIMIT_WINDOW_SECONDS = 60             # окно подсчёта попыток
RATE_LIMIT_MAX_ATTEMPTS = 10               # попыток с одного адреса за окно

RECOVERY_CODE_COUNT = 10

# --------------------------------------------------------------------------
# Почта
# --------------------------------------------------------------------------

# Mailpit: один бинарник, SMTP на 1025 и веб-почтовик на http://localhost:8025.
# Если SMTP недоступен, письма складываются в web/var/mail — демонстрация
# не ломается (см. mailer.py).
SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "1025"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
MAIL_FROM = os.environ.get("MAIL_FROM", "noreply@kuznyechik.local")

# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------

# Встроенные шрифты fpdf2 не содержат кириллицы, поэтому нужен TTF.
PDF_FONT_CANDIDATES = [
    os.environ.get("PDF_FONT", ""),
    "C:/Windows/Fonts/arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]

APP_TITLE = "Защищённая передача сообщений · ГОСТ"


def ensure_directories() -> None:
    """Создаёт рабочие каталоги и мастер-ключ при первом запуске."""
    for directory in (VAR_DIR, TMP_DIR, MAIL_DIR, SECRETS_DIR, DB_PATH.parent):
        directory.mkdir(parents=True, exist_ok=True)

    if not MASTER_KEY_PATH.exists():
        # 256 бит для «Кузнечика»: этим ключом шифруются ключи сообщений.
        MASTER_KEY_PATH.write_text(secrets.token_bytes(32).hex(), encoding="ascii")
        print(f"[config] создан новый мастер-ключ: {MASTER_KEY_PATH}")
        print("[config] потеряете этот файл — все сохранённые сообщения станут нечитаемыми")


def master_key() -> bytes:
    """Мастер-ключ сервера (256 бит) для шифрования ключей сообщений."""
    return bytes.fromhex(MASTER_KEY_PATH.read_text(encoding="ascii").strip())
