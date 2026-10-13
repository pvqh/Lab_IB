"""
Отправка почты.

Для демонстрации используется Mailpit — один исполняемый файл, который
поднимает SMTP на порту 1025 и веб-почтовик на http://localhost:8025.
Он перехватывает все письма приложения и показывает их в браузере.
Это удобнее личного ящика: код видно на экране, и ничего не зависит
от того, пропускает ли сеть порт 587.

Если SMTP недоступен, письмо записывается в web/var/mail/*.eml и путь
печатается в консоль. Демонстрация при этом не ломается, и в журнале
видно, что доставка не удалась.

Настоящий SMTP (например, Gmail с паролем приложения) включается
переменными окружения SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASSWORD.
"""

import smtplib
from email.message import EmailMessage

import config
import security


def send(to_address: str, subject: str, body: str) -> bool:
    """
    Отправляет письмо. Возвращает True при успешной доставке в SMTP.
    Ошибка доставки не должна ломать запрос пользователя, поэтому
    исключение не поднимается, а фиксируется в журнале.
    """
    message = EmailMessage()
    message["From"] = config.MAIL_FROM
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)

    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=5) as smtp:
            if config.SMTP_USER:
                smtp.starttls()
                smtp.login(config.SMTP_USER, config.SMTP_PASSWORD)
            smtp.send_message(message)
        security.audit("mail_sent", detail=f"{to_address}: {subject}")
        return True

    except OSError as error:
        path = _save_to_disk(message)
        print(f"[mailer] SMTP недоступен ({error}); письмо записано в {path}")
        security.audit("mail_failed", detail=f"{to_address}: {error}")
        return False


def _save_to_disk(message: EmailMessage):
    config.MAIL_DIR.mkdir(parents=True, exist_ok=True)
    filename = security.stamp().replace(":", "-") + "-" + str(abs(hash(message["To"])))[:6] + ".eml"
    path = config.MAIL_DIR / filename
    path.write_text(message.as_string(), encoding="utf-8")
    return path


def send_login_code(to_address: str, code: str) -> bool:
    return send(
        to_address,
        "Код подтверждения входа",
        f"Код подтверждения входа: {code}\n\n"
        f"Код действует {config.OTP_LIFETIME_SECONDS // 60} минут.\n"
        f"Если вы не входили в систему, просто проигнорируйте это письмо.\n")


def send_reset_link(to_address: str, link: str) -> bool:
    return send(
        to_address,
        "Восстановление пароля",
        f"Чтобы задать новый пароль, откройте ссылку:\n\n{link}\n\n"
        f"Ссылка действует {config.RESET_TOKEN_LIFETIME_SECONDS // 60} минут "
        f"и срабатывает один раз.\n"
        f"После смены пароля все открытые сессии будут закрыты.\n")
