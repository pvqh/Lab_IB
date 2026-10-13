"""
Три фактора входа и машина состояний входа.

Почему именно эти три. Фактор должен быть не «ещё одним паролем»,
а другой КАТЕГОРИЕЙ доказательства, иначе получается один фактор три раза:

    1. пароль             — то, что вы ЗНАЕТЕ
    2. код из письма       — то, к чему у вас есть ДОСТУП
    3. код TOTP            — то, что вы ДЕРЖИТЕ в руках (телефон с секретом)

Коды восстановления заменяют сразу факторы 2 и 3 — на случай потери
телефона и доступа к почте одновременно.

Главное в этом файле — то, что состояние входа лежит на СЕРВЕРЕ,
в таблице login_flows. Если хранить stage в скрытом поле формы или
в cookie, злоумышленник с одним только паролем подставит stage = 3
и войдёт — и тогда три фактора остаются только на схеме.
"""

import secrets

import pyotp

import config
import db
import security


# --------------------------------------------------------------------------
# Машина состояний входа
#
#   stage 1  пароль принят, ждём код из письма
#   stage 2  код из письма принят, ждём TOTP
#   (достижение stage 3 означает выдачу настоящей сессии)
# --------------------------------------------------------------------------

def start_flow(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with db.connect() as connection:
        connection.execute(
            "INSERT INTO login_flows(token, user_id, stage, created_at, expires_at) "
            "VALUES (?, ?, 1, ?, ?)",
            (token, user_id, security.stamp(),
             security.in_seconds(config.LOGIN_FLOW_LIFETIME_SECONDS)))
    return token


def load_flow(token: str | None, required_stage: int):
    """
    Возвращает запись процесса входа, только если он действительно
    находится на требуемой стадии. Проверка идёт из базы на каждом шаге,
    поэтому шаги нельзя ни пропустить, ни переиграть.
    """
    if not token:
        return None
    with db.connect() as connection:
        return connection.execute(
            "SELECT * FROM login_flows WHERE token = ? AND stage = ? AND expires_at > ?",
            (token, required_stage, security.stamp())).fetchone()


def advance_flow(token: str, new_stage: int) -> None:
    with db.connect() as connection:
        connection.execute("UPDATE login_flows SET stage = ? WHERE token = ?",
                           (new_stage, token))


def finish_flow(token: str) -> None:
    with db.connect() as connection:
        connection.execute("DELETE FROM login_flows WHERE token = ?", (token,))


# --------------------------------------------------------------------------
# Фактор 2: одноразовый код письмом
# --------------------------------------------------------------------------

def create_email_otp(user_id: int, purpose: str) -> str:
    """
    Создаёт шестизначный код и возвращает его ОТКРЫТЫМ — чтобы отправить
    письмом. В базу попадает только хеш: украденная база не должна
    выдавать действующие коды.
    """
    code = f"{secrets.randbelow(1_000_000):06d}"
    with db.connect() as connection:
        # Старые неиспользованные коды той же цели гасим: иначе у
        # пользователя одновременно действует несколько кодов.
        connection.execute(
            "UPDATE email_otps SET consumed_at = ? "
            "WHERE user_id = ? AND purpose = ? AND consumed_at IS NULL",
            (security.stamp(), user_id, purpose))
        connection.execute(
            "INSERT INTO email_otps(user_id, code_hash, purpose, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (user_id, security.hash_token(code), purpose,
             security.in_seconds(config.OTP_LIFETIME_SECONDS)))
    return code


def verify_email_otp(user_id: int, purpose: str, code: str) -> bool:
    """
    Проверяет код. Число попыток ограничено: шесть цифр — это миллион
    вариантов, которые без лимита перебираются скриптом за минуты.
    """
    with db.connect() as connection:
        row = connection.execute(
            "SELECT * FROM email_otps WHERE user_id = ? AND purpose = ? "
            "AND consumed_at IS NULL AND expires_at > ? ORDER BY id DESC LIMIT 1",
            (user_id, purpose, security.stamp())).fetchone()

        if row is None or row["attempts"] >= config.OTP_MAX_ATTEMPTS:
            return False

        if secrets.compare_digest(security.hash_token(code), row["code_hash"]):
            connection.execute("UPDATE email_otps SET consumed_at = ? WHERE id = ?",
                               (security.stamp(), row["id"]))
            return True

        attempts = row["attempts"] + 1
        # Исчерпал попытки — код гасится целиком, новый надо запрашивать заново.
        consumed = security.stamp() if attempts >= config.OTP_MAX_ATTEMPTS else None
        connection.execute("UPDATE email_otps SET attempts = ?, consumed_at = ? WHERE id = ?",
                           (attempts, consumed, row["id"]))
        return False


# --------------------------------------------------------------------------
# Фактор 3: TOTP (RFC 6238)
#
# Сервер и телефон хранят общий секрет и независимо считают код от
# текущего времени. Код нигде не передаётся, поэтому его нельзя
# подсмотреть в канале.
# --------------------------------------------------------------------------

def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(username: str, secret: str) -> str:
    """Строка otpauth://, которую кодируют в QR для Google Authenticator."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Kuznyechik")


def verify_totp(secret: str, code: str) -> bool:
    # valid_window=1 допускает соседний 30-секундный интервал: часы
    # на телефоне почти всегда уходят на несколько секунд.
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


# --------------------------------------------------------------------------
# Коды восстановления
# --------------------------------------------------------------------------

def create_recovery_codes(user_id: int) -> list[str]:
    """
    Генерирует коды, показывает их один раз, в базу кладёт только хеши.
    Каждый код одноразовый и заменяет оба оставшихся фактора.
    """
    codes = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}"
             for _ in range(config.RECOVERY_CODE_COUNT)]
    with db.connect() as connection:
        connection.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
        connection.executemany(
            "INSERT INTO recovery_codes(user_id, code_hash) VALUES (?, ?)",
            [(user_id, security.hash_token(code)) for code in codes])
    return codes


def use_recovery_code(user_id: int, code: str) -> bool:
    """Гасит код, если он подходит. Повторно тот же код не сработает."""
    candidate = security.hash_token(code.strip().lower())
    with db.connect() as connection:
        row = connection.execute(
            "SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? "
            "AND used_at IS NULL", (user_id, candidate)).fetchone()
        if row is None:
            return False
        connection.execute("UPDATE recovery_codes SET used_at = ? WHERE id = ?",
                           (security.stamp(), row["id"]))
        return True


def unused_recovery_code_count(user_id: int) -> int:
    with db.connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS count FROM recovery_codes "
            "WHERE user_id = ? AND used_at IS NULL", (user_id,)).fetchone()
    return row["count"]


# --------------------------------------------------------------------------
# Сброс пароля
# --------------------------------------------------------------------------

def create_reset_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with db.connect() as connection:
        connection.execute(
            "INSERT INTO password_resets(user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user_id, security.hash_token(token),
             security.in_seconds(config.RESET_TOKEN_LIFETIME_SECONDS)))
    return token


def consume_reset_token(token: str) -> int | None:
    """Возвращает id пользователя и гасит токен, либо None."""
    with db.connect() as connection:
        row = connection.execute(
            "SELECT * FROM password_resets WHERE token_hash = ? AND used_at IS NULL "
            "AND expires_at > ?", (security.hash_token(token), security.stamp())).fetchone()
        if row is None:
            return None
        connection.execute("UPDATE password_resets SET used_at = ? WHERE id = ?",
                           (security.stamp(), row["id"]))
        return row["user_id"]
