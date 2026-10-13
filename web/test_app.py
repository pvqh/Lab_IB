"""
Сквозной тест веб-приложения: один проход по всему маршруту пользователя
плюс проверки того, что защита действительно срабатывает.

Это и регрессионный тест, и исполняемая документация: по нему видно,
в каком порядке ходят запросы и что именно система обязана запрещать.

Запуск (из каталога web):
    .venv\\Scripts\\python test_app.py

Тест работает на отдельной базе в var/test.sqlite3 и на ключе key_dev
(2048 бит) с малым числом итераций KDF — иначе один прогон занял бы
минуты из-за 32768-битной RSA.
"""

import os
import sys
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent

# Настройки задаются ДО импорта config: модуль читает окружение при загрузке.
os.environ.setdefault("DB_PATH", str(WEB_DIR / "var" / "test.sqlite3"))
os.environ.setdefault("RSA_KEY_PREFIX", str(WEB_DIR.parent / "ЗИ_ЛР" / "key_dev"))
os.environ.setdefault("KDF_ITERATIONS", "50")
os.environ.setdefault("SMTP_HOST", "127.0.0.1")
os.environ.setdefault("SMTP_PORT", "1")        # заведомо закрытый порт: письма идут в файл

Path(os.environ["DB_PATH"]).unlink(missing_ok=True)

import pyotp                       # noqa: E402
from fastapi.testclient import TestClient   # noqa: E402

import app as application          # noqa: E402
import db                          # noqa: E402
import security                    # noqa: E402

passed = 0
failed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  OK   {name}")
    else:
        failed += 1
        print(f"  FAIL {name}" + (f" — {detail}" if detail else ""))


def latest_otp_code(user_id: int) -> str:
    """
    Достаёт код из письма.

    В базе лежит только хеш, поэтому перебираем миллион шестизначных
    вариантов? Нет — письмо сохраняется в var/mail, и код берётся оттуда,
    ровно как это сделал бы человек, открывший почту.
    """
    import email
    import config

    newest = max(config.MAIL_DIR.glob("*.eml"), key=lambda path: path.stat().st_mtime)
    # Тело письма с кириллицей уходит в base64, поэтому читаем его
    # разборщиком почты, а не как простой текст.
    message = email.message_from_string(newest.read_text(encoding="utf-8"))
    body = message.get_payload(decode=True).decode("utf-8")
    for token in body.split():
        if token.isdigit() and len(token) == 6:
            return token
    raise AssertionError("в письме не найден шестизначный код")


def csrf_of(client: TestClient) -> str:
    """CSRF-токен текущей сессии — его же приложение кладёт в формы."""
    session = security.load_session(client.cookies.get("session"))
    return session["csrf_token"]


def main() -> int:
    client = TestClient(application.app, base_url="http://testserver")

    print("Открытые страницы")
    check("главная открывается", client.get("/").status_code == 200)
    check("страница проверки подписи открыта гостю", client.get("/verify").status_code == 200)
    check("история закрыта для гостя",
          client.get("/history", follow_redirects=False).status_code == 303)
    check("админка закрыта для гостя",
          client.get("/admin", follow_redirects=False).status_code == 303)

    print("\nРегистрация и проверка ввода")
    weak = client.post("/register", data={"username": "ab", "email": "не-почта",
                                          "password": "123", "password_repeat": "123"})
    check("слабые данные отвергнуты", "Пароль должен содержать" in weak.text)

    password = "Pervyi-Parol-2026!"
    response = client.post("/register", data={
        "username": "ivanov", "email": "ivanov@example.com",
        "password": password, "password_repeat": password})
    check("регистрация прошла", "Учётная запись создана" in response.text)

    user = security.find_user("ivanov")
    check("пароль не хранится открытым", password not in str(dict(user)))
    check("соль у пользователя своя", len(user["pwd_salt"]) == 32)
    check("число итераций сохранено", user["pwd_iters"] == 50)

    print("\nВход: три фактора по очереди")
    secret = user["totp_secret"]

    # Нельзя перепрыгнуть на третий шаг, не пройдя первые два.
    check("шаг 3 недоступен без шага 1",
          client.get("/login/totp", follow_redirects=False).headers.get("location") == "/login")

    bad = client.post("/login", data={"username": "ivanov", "password": "НеТотПароль1!"})
    check("неверный пароль отвергнут", "Неверное имя пользователя или пароль" in bad.text)

    unknown = client.post("/login", data={"username": "нетакого", "password": "Что-то1!"})
    check("сообщение одинаково для несуществующего имени",
          "Неверное имя пользователя или пароль" in unknown.text)

    step1 = client.post("/login", data={"username": "ivanov", "password": password},
                        follow_redirects=False)
    check("фактор 1 пройден", step1.headers.get("location") == "/login/email")

    check("шаг 3 недоступен сразу после шага 1",
          client.get("/login/totp", follow_redirects=False).headers.get("location") == "/login")

    wrong_code = client.post("/login/email", data={"code": "000000"})
    check("неверный код из письма отвергнут", "Неверный или истёкший код" in wrong_code.text)

    step2 = client.post("/login/email", data={"code": latest_otp_code(user["id"])},
                        follow_redirects=False)
    check("фактор 2 пройден", step2.headers.get("location") == "/login/totp")

    step3 = client.post("/login/totp", data={"code": pyotp.TOTP(secret).now()},
                        follow_redirects=False)
    check("фактор 3 пройден, выдана сессия", step3.headers.get("location") == "/encrypt")
    check("cookie сессии установлена", client.cookies.get("session") is not None)

    print("\nЗащита форм")
    no_csrf = client.post("/encrypt", data={"csrf_token": "подделка",
                                            "method": "kuznyechik", "plaintext": "тест"})
    check("форма без верного CSRF-токена отклонена", no_csrf.status_code == 400)

    print("\nШифрование Кузнечиком")
    token = csrf_of(client)
    secret_text = "Строго секретно: атака на рассвете. Текст длиннее одного блока в 16 байт."
    created = client.post("/encrypt", data={"csrf_token": token, "method": "kuznyechik",
                                            "plaintext": secret_text}, follow_redirects=False)
    message_id = int(created.headers["location"].rsplit("/", 1)[1])
    check("сообщение создано", created.status_code == 303)

    with db.connect() as connection:
        row = connection.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    check("открытого текста в базе нет", secret_text not in str(dict(row)))
    check("шифртекст той же длины, что текст",
          len(bytes.fromhex(row["ciphertext_hex"])) == len(secret_text.encode("utf-8")))
    check("ключ сообщения хранится в обёртке", bool(row["wrapped_key_hex"]))
    check("IV сохранён", len(bytes.fromhex(row["iv_hex"])) == 8)

    detail = client.get(f"/history/{message_id}")
    check("расшифровка по требованию вернула текст", secret_text in detail.text)

    print("\nШифрование RSA")
    token = csrf_of(client)
    rsa_text = "Короткое сообщение для RSA"
    created = client.post("/encrypt", data={"csrf_token": token, "method": "rsa",
                                            "plaintext": rsa_text}, follow_redirects=False)
    rsa_id = int(created.headers["location"].rsplit("/", 1)[1])
    check("расшифровка RSA вернула текст", rsa_text in client.get(f"/history/{rsa_id}").text)

    print("\nPDF и электронная подпись")
    pdf = client.get(f"/history/{message_id}/pdf")
    signature = client.get(f"/history/{message_id}/pdf.sig")
    check("PDF отдаётся", pdf.status_code == 200 and pdf.content[:4] == b"%PDF")
    check("подпись отдаётся", signature.status_code == 200)

    verified = client.post("/verify", files={
        "document": ("message.pdf", pdf.content, "application/pdf"),
        "signature": ("message.pdf.sig", signature.content, "text/plain")})
    check("подпись подтверждается", "Подпись верна" in verified.text)

    tampered = bytearray(pdf.content)
    tampered[len(tampered) // 2] ^= 0x01        # меняем один бит документа
    broken = client.post("/verify", files={
        "document": ("message.pdf", bytes(tampered), "application/pdf"),
        "signature": ("message.pdf.sig", signature.content, "text/plain")})
    check("изменённый документ не проходит проверку",
          "НЕ соответствует" in broken.text)

    print("\nРазграничение доступа")
    check("обычному пользователю админка запрещена", client.get("/admin").status_code == 403)

    # Второй пользователь не должен видеть чужое сообщение.
    other_password = "Vtoroi-Parol-2026!"
    client2 = TestClient(application.app, base_url="http://testserver")
    client2.post("/register", data={"username": "petrov", "email": "petrov@example.com",
                                    "password": other_password,
                                    "password_repeat": other_password})
    petrov = security.find_user("petrov")
    client2.post("/login", data={"username": "petrov", "password": other_password})
    client2.post("/login/email", data={"code": latest_otp_code(petrov["id"])})
    client2.post("/login/totp", data={"code": pyotp.TOTP(petrov["totp_secret"]).now()})
    check("второй пользователь вошёл", client2.cookies.get("session") is not None)
    check("чужое сообщение недоступно",
          client2.get(f"/history/{message_id}").status_code == 404)
    check("в своей истории чужого нет",
          f'/history/{message_id}"' not in client2.get("/history").text)

    print("\nАдминистратор")
    admin_password = "Administrator-2026!"
    admin_secret = _create_admin("root", "root@example.com", admin_password)
    admin = TestClient(application.app, base_url="http://testserver")
    admin.post("/login", data={"username": "root", "password": admin_password})
    admin.post("/login/email", data={"code": latest_otp_code(security.find_user("root")["id"])})
    admin.post("/login/totp", data={"code": pyotp.TOTP(admin_secret).now()})
    check("администратор вошёл", admin.get("/admin").status_code == 200)
    check("администратор видит все сообщения",
          str(message_id) in admin.get("/admin/messages").text)
    check("администратор может открыть чужое сообщение",
          admin.get(f"/history/{message_id}").status_code == 200)

    # Отключаем RSA и проверяем, что это действительно запрещает метод.
    admin.post("/admin/methods", data={"csrf_token": csrf_of(admin), "kuz_enabled": "1"})
    check("RSA отключён в настройках", "rsa" not in db.enabled_methods())
    check("форма больше не предлагает RSA", "value=\"rsa\"" not in client.get("/encrypt").text)

    blocked = client.post("/encrypt", data={"csrf_token": csrf_of(client), "method": "rsa",
                                            "plaintext": "попытка в обход формы"})
    check("прямой POST с отключённым методом отклонён", blocked.status_code == 403)
    admin.post("/admin/methods", data={"csrf_token": csrf_of(admin),
                                       "kuz_enabled": "1", "rsa_enabled": "1"})

    print("\nЖурнал")
    with db.connect() as connection:
        actions = {row["action"] for row in
                   connection.execute("SELECT DISTINCT action FROM audit_log").fetchall()}
    for action in ("register", "login_success", "login_failed", "encrypt",
                   "pdf_export", "admin_methods", "signature_verify"):
        check(f"в журнале есть «{action}»", action in actions)

    print(f"\nитого: пройдено {passed}, провалено {failed}")
    return 0 if failed == 0 else 1


def _create_admin(username: str, email: str, password: str) -> str:
    import threefa
    secret = threefa.new_totp_secret()
    user_id = security.create_user(username, email, password, "admin", secret)
    threefa.create_recovery_codes(user_id)
    return secret


if __name__ == "__main__":
    sys.exit(main())
