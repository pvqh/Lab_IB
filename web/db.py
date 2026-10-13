"""
База данных: SQLite, чистый sqlite3, без ORM.

Два правила на весь модуль и на всё приложение:

1. Любое значение попадает в SQL только через параметр «?».
   f-строка внутри execute() — это SQL-инъекция, других вариантов нет.
2. Схема создаётся одним вызовом init() при старте; миграций нет,
   потому что проект учебный и база пересоздаётся.

Схема повторяет план лабораторной работы. Единственное отклонение:
ключи RSA лежат файлами в ЗИ_ЛР (их создаёт crypto_cli rsa-keygen),
поэтому вместо таблицы rsa_keys в сообщениях хранится key_id —
имя набора файлов, которым сообщение было зашифровано. Это позволяет
сменить ключ и при этом понимать, чем расшифровывать старые записи.
"""

import sqlite3

import config

SCHEMA = """
-- Пользователи. Пароль хранится только как соль + хеш + число итераций.
-- Число итераций хранится у каждого пользователя, чтобы его можно было
-- поднять в будущем, не ломая уже существующие записи.
CREATE TABLE IF NOT EXISTS users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT NOT NULL UNIQUE,
    email                TEXT NOT NULL UNIQUE,
    pwd_hash             TEXT NOT NULL,
    pwd_salt             TEXT NOT NULL,
    pwd_iters            INTEGER NOT NULL,
    role                 TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    totp_secret          TEXT NOT NULL,
    is_active            INTEGER NOT NULL DEFAULT 1,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL,
    failed_logins        INTEGER NOT NULL DEFAULT 0,
    locked_until         TEXT
);

-- Коды восстановления. Каждый заменяет сразу второй и третий факторы,
-- одноразовый. Хранятся только хеши.
CREATE TABLE IF NOT EXISTS recovery_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES users(id),
    code_hash TEXT NOT NULL,
    used_at   TEXT
);

-- Одноразовые коды из письма. Хранятся хешами: украденная база
-- не должна выдавать действующие коды.
CREATE TABLE IF NOT EXISTS email_otps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    code_hash   TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    consumed_at TEXT,
    attempts    INTEGER NOT NULL DEFAULT 0
);

-- Состояние незавершённого входа. Живёт на сервере, а не в cookie:
-- иначе злоумышленник просто подставил бы stage=3 и обошёл два фактора.
CREATE TABLE IF NOT EXISTS login_flows (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token      TEXT NOT NULL UNIQUE,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    stage      INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- Сессии. В cookie уходит только случайный токен; роль и личность
-- читаются из этой таблицы при каждом запросе.
CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token      TEXT NOT NULL UNIQUE,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- Сообщения. Открытого текста здесь нет и быть не должно: система,
-- хранящая все сообщения в открытом виде, обессмысливает сама себя.
-- Расшифровка делается по требованию, когда пользователь открывает запись.
--   ciphertext_hex  — шифртекст
--   iv_hex          — IV режима CTR (для RSA не используется)
--   wrapped_key_hex — ключ сообщения, зашифрованный мастер-ключом
--   wrap_iv_hex     — IV, которым зашифрован сам ключ сообщения
CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    method          TEXT NOT NULL CHECK (method IN ('kuznyechik', 'rsa')),
    ciphertext_hex  TEXT NOT NULL,
    iv_hex          TEXT,
    wrapped_key_hex TEXT,
    wrap_iv_hex     TEXT,
    key_id          TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

-- Восстановление пароля: одноразовый токен, высылаемый письмом.
CREATE TABLE IF NOT EXISTS password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT
);

-- Глобальные переключатели (какие методы шифрования разрешены).
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Журнал действий. Нужен и для разбора инцидентов, и как основа
-- ограничения частоты запросов (см. security.recent_attempts).
CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action  TEXT NOT NULL,
    ip      TEXT,
    ts      TEXT NOT NULL,
    detail  TEXT
);

CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, ts);
"""

DEFAULT_SETTINGS = {
    "kuz_enabled": "1",
    "rsa_enabled": "1",
}


def connect() -> sqlite3.Connection:
    """Соединение с включённым доступом к полям по имени."""
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(config.DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init() -> None:
    """Создаёт схему и значения по умолчанию. Безопасно вызывать повторно."""
    with connect() as connection:
        connection.executescript(SCHEMA)
        for key, value in DEFAULT_SETTINGS.items():
            connection.execute(
                "INSERT INTO settings(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO NOTHING", (key, value))


# --------------------------------------------------------------------------
# Настройки
# --------------------------------------------------------------------------

def get_setting(key: str, default: str = "") -> str:
    with connect() as connection:
        row = connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with connect() as connection:
        connection.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))


def enabled_methods() -> list[str]:
    """Методы шифрования, разрешённые администратором."""
    methods = []
    if get_setting("kuz_enabled") == "1":
        methods.append("kuznyechik")
    if get_setting("rsa_enabled") == "1":
        methods.append("rsa")
    return methods
