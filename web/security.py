"""
Пароли, сессии, роли, журнал и ограничение частоты запросов.

Здесь собрано всё, что отвечает на вопрос «кто этот пользователь и что
ему можно». Три факторы входа лежат отдельно, в threefa.py.
"""

import re
import secrets
from datetime import datetime, timedelta, timezone

import config
import crypto
import db

# --------------------------------------------------------------------------
# Время
#
# Всё хранится в UTC в формате ISO: SQLite не имеет типа даты, а строки
# ISO в UTC сравниваются лексикографически, то есть обычным "<" в SQL.
# --------------------------------------------------------------------------

def now() -> datetime:
    return datetime.now(timezone.utc)


def stamp(moment: datetime | None = None) -> str:
    return (moment or now()).isoformat(timespec="seconds")


def in_seconds(seconds: int) -> str:
    return stamp(now() + timedelta(seconds=seconds))


# --------------------------------------------------------------------------
# Проверка ввода
#
# Проверяется ВСЁ на сервере. Атрибуты pattern в HTML-формах — это только
# удобство для пользователя: POST-запрос можно отправить и напрямую.
# --------------------------------------------------------------------------

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,32}$")

# Прагматичная проверка адреса. Полностью совместимый с RFC 5322 регэксп
# имеет длину в тысячи символов, никем не поддерживается и всё равно не
# отвечает на главный вопрос — доходит ли письмо. Поэтому простая проверка
# формы плюс реальное письмо с кодом подтверждения.
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")

# Для пароля в коде используются четыре отдельные проверки, а не одна
# цепочка с lookahead: так пользователю можно сказать, какое именно
# правило он нарушил. Эквивалентная «одной строкой» запись для отчёта:
#   ^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{12,}$
PASSWORD_RULES = [
    (re.compile(r".{12,}"), "не короче 12 символов"),
    (re.compile(r"[a-z]"), "хотя бы одна строчная буква"),
    (re.compile(r"[A-Z]"), "хотя бы одна заглавная буква"),
    (re.compile(r"\d"), "хотя бы одна цифра"),
    (re.compile(r"[^\w\s]"), "хотя бы один специальный символ"),
]


def validate_username(value: str) -> str | None:
    if not USERNAME_PATTERN.match(value):
        return "Имя: 3–32 символа, только латинские буквы, цифры и подчёркивание."
    return None


def validate_email(value: str) -> str | None:
    if not EMAIL_PATTERN.match(value):
        return "Адрес электронной почты выглядит неверно."
    return None


def validate_password(value: str) -> str | None:
    missing = [description for pattern, description in PASSWORD_RULES
               if not pattern.search(value)]
    if missing:
        return "Пароль должен содержать: " + ", ".join(missing) + "."
    return None


# --------------------------------------------------------------------------
# Пароли
# --------------------------------------------------------------------------

def hash_password(password: str) -> tuple[str, str, int]:
    """
    Возвращает (hex хеша, hex соли, число итераций).

    Соль случайна и уникальна для каждого пользователя: это обесценивает
    радужные таблицы — предвычисленный словарь годится максимум для
    одного пользователя, и то если атакующий знал соль заранее.
    """
    salt = crypto.random_bytes(config.SALT_BYTES)
    iterations = config.KDF_ITERATIONS
    digest = crypto.kdf(password, salt, iterations)
    return digest.hex(), salt.hex(), iterations


def verify_password(password: str, stored_hash: str, stored_salt: str, iterations: int) -> bool:
    """
    Сравнение через compare_digest, а не через ==.

    Обычное сравнение строк выходит на первом несовпавшем байте, и по
    времени ответа можно побайтно угадывать правильное значение.
    compare_digest работает за постоянное время.
    """
    digest = crypto.kdf(password, bytes.fromhex(stored_salt), iterations)
    return secrets.compare_digest(digest.hex(), stored_hash)


def hash_token(token: str) -> str:
    """
    Хеш одноразового значения (кода из письма, кода восстановления,
    токена сброса пароля) для хранения в базе.

    Итерации не нужны: это не пароль, а случайное значение с высокой
    энтропией — перебирать его бессмысленно, поэтому достаточно
    одного Стрибога.
    """
    return crypto.stribog(token.encode("utf-8"), 512).hex()


# --------------------------------------------------------------------------
# Журнал и ограничение частоты
# --------------------------------------------------------------------------

def audit(action: str, user_id: int | None = None, ip: str | None = None,
          detail: str | None = None) -> None:
    """
    Записывает факт в журнал.

    Журнал — это про обнаружение, а не про предотвращение: он отвечает
    на вопрос «что произошло», когда защита уже не сработала.
    """
    with db.connect() as connection:
        connection.execute(
            "INSERT INTO audit_log(user_id, action, ip, ts, detail) VALUES (?, ?, ?, ?, ?)",
            (user_id, action, ip, stamp(), detail))


def recent_attempts(action: str, ip: str | None) -> int:
    """Сколько раз это действие выполнялось с данного адреса за окно."""
    since = in_seconds(-config.RATE_LIMIT_WINDOW_SECONDS)
    with db.connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS count FROM audit_log "
            "WHERE action = ? AND ip IS ? AND ts >= ?", (action, ip, since)).fetchone()
    return row["count"]


def rate_limited(action: str, ip: str | None) -> bool:
    """
    True, если с этого адреса слишком много попыток.

    Считается по журналу, отдельной таблицы счётчиков нет: журнал всё
    равно ведётся, и так видно, откуда взялась блокировка.
    """
    return recent_attempts(action, ip) >= config.RATE_LIMIT_MAX_ATTEMPTS


# --------------------------------------------------------------------------
# Пользователи
# --------------------------------------------------------------------------

def find_user(username: str):
    with db.connect() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def find_user_by_id(user_id: int):
    with db.connect() as connection:
        return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def find_user_by_email(email: str):
    with db.connect() as connection:
        return connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def is_locked(user) -> bool:
    return bool(user["locked_until"]) and user["locked_until"] > stamp()


def register_failed_login(user) -> None:
    """
    Увеличивает счётчик неудач и блокирует учётную запись после предела.

    Без этого шесть цифр второго фактора или слабый пароль перебираются
    автоматом за минуты.
    """
    failures = user["failed_logins"] + 1
    locked_until = in_seconds(config.LOCKOUT_SECONDS) if failures >= config.MAX_FAILED_LOGINS else None
    with db.connect() as connection:
        connection.execute(
            "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
            (failures, locked_until, user["id"]))


def reset_failed_logins(user_id: int) -> None:
    with db.connect() as connection:
        connection.execute(
            "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user_id,))


def create_user(username: str, email: str, password: str, role: str,
                totp_secret: str, must_change_password: bool = False) -> int:
    pwd_hash, pwd_salt, iterations = hash_password(password)
    with db.connect() as connection:
        cursor = connection.execute(
            "INSERT INTO users(username, email, pwd_hash, pwd_salt, pwd_iters, role, "
            "totp_secret, created_at, must_change_password) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (username, email, pwd_hash, pwd_salt, iterations, role, totp_secret,
             stamp(), int(must_change_password)))
        return cursor.lastrowid


def change_password(user_id: int, password: str) -> None:
    pwd_hash, pwd_salt, iterations = hash_password(password)
    with db.connect() as connection:
        connection.execute(
            "UPDATE users SET pwd_hash = ?, pwd_salt = ?, pwd_iters = ?, "
            "must_change_password = 0 WHERE id = ?",
            (pwd_hash, pwd_salt, iterations, user_id))


# --------------------------------------------------------------------------
# Сессии
#
# В cookie уходит только случайный токен. Роль в cookie не кладётся
# никогда: иначе её можно было бы подменить. При каждом запросе роль
# читается из базы.
# --------------------------------------------------------------------------

def create_session(user_id: int) -> tuple[str, str]:
    """Возвращает (токен сессии, CSRF-токен)."""
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    with db.connect() as connection:
        connection.execute(
            "INSERT INTO sessions(token, user_id, csrf_token, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (token, user_id, csrf_token, stamp(),
             in_seconds(config.SESSION_LIFETIME_SECONDS)))
    return token, csrf_token


def load_session(token: str | None):
    """Сессия и пользователь по токену, либо None."""
    if not token:
        return None
    with db.connect() as connection:
        return connection.execute(
            "SELECT s.token, s.csrf_token, u.* FROM sessions s "
            "JOIN users u ON u.id = s.user_id "
            "WHERE s.token = ? AND s.expires_at > ? AND u.is_active = 1",
            (token, stamp())).fetchone()


def delete_session(token: str) -> None:
    with db.connect() as connection:
        connection.execute("DELETE FROM sessions WHERE token = ?", (token,))


def delete_all_sessions(user_id: int) -> None:
    """Вызывается при смене пароля: старые сессии больше не действуют."""
    with db.connect() as connection:
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
