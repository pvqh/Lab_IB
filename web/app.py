"""
Веб-приложение: регистрация, трёхфакторный вход, шифрование, история,
PDF с электронной подписью, панель администратора.

Страницы отдаются сервером через шаблоны Jinja2 — отдельного фронтенда
нет намеренно: две кодовые базы вместо одной не дали бы ничего, кроме
лишней работы.

Повторяющиеся правила, которые видно в каждом обработчике:

  * роль читается из базы при каждом запросе (require_user/require_admin),
    а не из cookie — cookie подделывается;
  * любая форма, меняющая состояние, проверяет CSRF-токен;
  * выборки сообщений всегда ограничены user_id из сессии, а не из URL,
    иначе достаточно поправить адрес, чтобы прочитать чужое;
  * каждое значение уходит в SQL только параметром «?».
"""

import base64
import io
import secrets
import sqlite3
from pathlib import Path

import qrcode
from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import config
import crypto
import db
import documents
import mailer
import security
import threefa

config.ensure_directories()
db.init()

app = FastAPI(title=config.APP_TITLE, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=config.WEB_DIR / "static"), name="static")
templates = Jinja2Templates(directory=config.WEB_DIR / "templates")

LOGIN_FLOW_COOKIE = "login_flow"


# ==========================================================================
#  Общие помощники
# ==========================================================================

def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def render(request: Request, template: str, **context) -> HTMLResponse:
    """Обёртка над шаблонизатором: подмешивает текущего пользователя и заголовок."""
    session = security.load_session(request.cookies.get(config.SESSION_COOKIE))
    context.setdefault("user", session)
    context.setdefault("csrf_token", session["csrf_token"] if session else "")
    context.setdefault("title", config.APP_TITLE)
    return templates.TemplateResponse(request, template, context)


def redirect(path: str) -> RedirectResponse:
    # 303 заставляет браузер сделать GET после POST — иначе обновление
    # страницы повторно отправит форму.
    return RedirectResponse(path, status_code=303)


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(
        config.SESSION_COOKIE, token,
        httponly=True,       # недоступна из JavaScript: XSS не украдёт сессию
        samesite="lax",      # не уходит на сторонние POST-запросы
        secure=False,        # поставить True при работе по HTTPS
        max_age=config.SESSION_LIFETIME_SECONDS,
        path="/")


# ---- зависимости доступа -------------------------------------------------

def require_user(request: Request):
    """Любой вошедший пользователь. Иначе — на страницу входа."""
    session = security.load_session(request.cookies.get(config.SESSION_COOKIE))
    if session is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return session


def require_admin(request: Request):
    """
    Только администратор.

    Одна зависимость на все административные маршруты. Забытая проверка
    на одном маршруте — самая частая уязвимость в учебных проектах
    и первое, что проверяет экзаменатор, поэтому проверка здесь одна
    и подключается явно к каждому маршруту.
    """
    session = require_user(request)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Требуются права администратора")
    return session


def check_csrf(request: Request, token: str) -> None:
    """
    Сверяет токен формы с токеном сессии.

    Без этого чужой сайт может отправить от имени пользователя POST
    на наш адрес, и браузер приложит cookie сессии. Токен знает только
    наша страница, поэтому подделать запрос не получается.
    """
    session = security.load_session(request.cookies.get(config.SESSION_COOKIE))
    if session is None or not secrets_equal(token, session["csrf_token"]):
        raise HTTPException(status_code=400, detail="Неверный CSRF-токен. Обновите страницу.")


def secrets_equal(left: str, right: str) -> bool:
    """
    Сравнение за постоянное время.

    Сравниваются байты, а не строки: compare_digest отказывается работать
    со строками, содержащими не-ASCII, а значение приходит из формы —
    то есть может быть любым. Без этого произвольный ввод ронял бы
    обработчик с ошибкой 500 вместо честного отказа.
    """
    return secrets.compare_digest((left or "").encode("utf-8"),
                                  (right or "").encode("utf-8"))


# ==========================================================================
#  Публичные страницы
# ==========================================================================

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return render(request, "index.html", rsa_bits=_rsa_bits_or_none())


def _rsa_bits_or_none():
    try:
        return crypto.rsa_modulus_bits()
    except OSError:
        return None


# ==========================================================================
#  Регистрация
# ==========================================================================

@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return render(request, "register.html")


@app.post("/register", response_class=HTMLResponse)
def register(request: Request,
             username: str = Form(...),
             email: str = Form(...),
             password: str = Form(...),
             password_repeat: str = Form(...)):
    values = {"username": username, "email": email}

    # Проверка только на сервере имеет значение: атрибуты pattern в форме
    # пользователь обходит одним curl.
    errors = [error for error in (security.validate_username(username),
                                  security.validate_email(email),
                                  security.validate_password(password)) if error]
    if password != password_repeat:
        errors.append("Пароли не совпадают.")
    if errors:
        return render(request, "register.html", errors=errors, values=values)

    secret = threefa.new_totp_secret()
    try:
        user_id = security.create_user(username, email, password, "user", secret)
    except sqlite3.IntegrityError:
        return render(request, "register.html", values=values,
                      errors=["Такое имя или адрес уже зарегистрированы."])

    codes = threefa.create_recovery_codes(user_id)
    security.audit("register", user_id=user_id, ip=client_ip(request), detail=username)

    # Секрет TOTP и коды восстановления показываются ровно один раз.
    return render(request, "register_done.html",
                  username=username,
                  codes=codes,
                  totp_secret=secret,
                  qr_data_uri=_qr_data_uri(threefa.totp_uri(username, secret)))


def _qr_data_uri(text: str) -> str:
    """QR-код как data: URI — страница остаётся самодостаточной."""
    image = qrcode.make(text)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


# ==========================================================================
#  Вход: три фактора по очереди
#
#  Стадия хранится в таблице login_flows, в браузер уходит только
#  случайный токен процесса. Каждый шаг заново читает стадию из базы,
#  поэтому порядок нельзя ни нарушить, ни пропустить.
# ==========================================================================

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return render(request, "login.html")


@app.post("/login")
def login_password(request: Request,
                   username: str = Form(...),
                   password: str = Form(...)):
    ip = client_ip(request)

    if security.rate_limited("login_attempt", ip):
        return render(request, "login.html",
                      errors=["Слишком много попыток входа. Подождите минуту."])
    security.audit("login_attempt", ip=ip, detail=username)

    user = security.find_user(username)

    # Один и тот же текст для «нет такого пользователя» и «неверный пароль»:
    # разные сообщения позволяют перебором выяснить, какие имена существуют.
    wrong = ["Неверное имя пользователя или пароль."]

    if user is None:
        return render(request, "login.html", errors=wrong)
    if security.is_locked(user):
        return render(request, "login.html",
                      errors=["Учётная запись временно заблокирована. "
                              f"Повторите через {config.LOCKOUT_SECONDS // 60} минут."])
    if not user["is_active"]:
        return render(request, "login.html", errors=["Учётная запись отключена."])

    if not security.verify_password(password, user["pwd_hash"], user["pwd_salt"],
                                    user["pwd_iters"]):
        security.register_failed_login(user)
        security.audit("login_failed", user_id=user["id"], ip=ip, detail="пароль")
        return render(request, "login.html", errors=wrong)

    # Фактор 1 пройден. Фактор 2 — код письмом.
    token = threefa.start_flow(user["id"])
    code = threefa.create_email_otp(user["id"], "login")
    delivered = mailer.send_login_code(user["email"], code)
    security.audit("login_factor1_ok", user_id=user["id"], ip=ip)

    response = redirect("/login/email")
    response.set_cookie(LOGIN_FLOW_COOKIE, token, httponly=True, samesite="lax",
                        max_age=config.LOGIN_FLOW_LIFETIME_SECONDS, path="/")
    if not delivered:
        response.set_cookie("mail_warning", "1", max_age=60, path="/")
    return response


@app.get("/login/email", response_class=HTMLResponse)
def login_email_form(request: Request):
    flow = threefa.load_flow(request.cookies.get(LOGIN_FLOW_COOKIE), required_stage=1)
    if flow is None:
        return redirect("/login")
    return render(request, "login_email.html",
                  mail_undelivered=request.cookies.get("mail_warning") == "1")


@app.post("/login/email")
def login_email(request: Request, code: str = Form(...)):
    ip = client_ip(request)
    flow = threefa.load_flow(request.cookies.get(LOGIN_FLOW_COOKIE), required_stage=1)
    if flow is None:
        return redirect("/login")

    if not threefa.verify_email_otp(flow["user_id"], "login", code.strip()):
        security.audit("login_failed", user_id=flow["user_id"], ip=ip, detail="код из письма")
        return render(request, "login_email.html",
                      errors=["Неверный или истёкший код."])

    threefa.advance_flow(flow["token"], 2)
    security.audit("login_factor2_ok", user_id=flow["user_id"], ip=ip)
    return redirect("/login/totp")


@app.get("/login/totp", response_class=HTMLResponse)
def login_totp_form(request: Request):
    flow = threefa.load_flow(request.cookies.get(LOGIN_FLOW_COOKIE), required_stage=2)
    if flow is None:
        return redirect("/login")
    return render(request, "login_totp.html")


@app.post("/login/totp")
def login_totp(request: Request, code: str = Form(...)):
    ip = client_ip(request)
    flow = threefa.load_flow(request.cookies.get(LOGIN_FLOW_COOKIE), required_stage=2)
    if flow is None:
        return redirect("/login")

    user = security.find_user_by_id(flow["user_id"])
    if not threefa.verify_totp(user["totp_secret"], code):
        security.register_failed_login(user)
        security.audit("login_failed", user_id=user["id"], ip=ip, detail="TOTP")
        return render(request, "login_totp.html", errors=["Неверный код приложения."])

    return _complete_login(flow, user, ip, "три фактора")


@app.get("/login/recovery", response_class=HTMLResponse)
def login_recovery_form(request: Request):
    # Код восстановления заменяет сразу факторы 2 и 3, поэтому он
    # принимается и на стадии 1, и на стадии 2.
    for stage in (1, 2):
        if threefa.load_flow(request.cookies.get(LOGIN_FLOW_COOKIE), stage):
            return render(request, "login_recovery.html")
    return redirect("/login")


@app.post("/login/recovery")
def login_recovery(request: Request, code: str = Form(...)):
    ip = client_ip(request)
    flow = (threefa.load_flow(request.cookies.get(LOGIN_FLOW_COOKIE), 1)
            or threefa.load_flow(request.cookies.get(LOGIN_FLOW_COOKIE), 2))
    if flow is None:
        return redirect("/login")

    if not threefa.use_recovery_code(flow["user_id"], code):
        security.audit("login_failed", user_id=flow["user_id"], ip=ip,
                       detail="код восстановления")
        return render(request, "login_recovery.html",
                      errors=["Код не найден или уже использован."])

    user = security.find_user_by_id(flow["user_id"])
    return _complete_login(flow, user, ip, "код восстановления")


def _complete_login(flow, user, ip: str, how: str):
    """Выдаёт настоящую сессию и убирает процесс входа."""
    threefa.finish_flow(flow["token"])
    security.reset_failed_logins(user["id"])
    token, _ = security.create_session(user["id"])
    security.audit("login_success", user_id=user["id"], ip=ip, detail=how)

    target = "/password/change" if user["must_change_password"] else "/encrypt"
    response = redirect(target)
    set_session_cookie(response, token)
    response.delete_cookie(LOGIN_FLOW_COOKIE, path="/")
    response.delete_cookie("mail_warning", path="/")
    return response


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    check_csrf(request, csrf_token)
    token = request.cookies.get(config.SESSION_COOKIE)
    session = security.load_session(token)
    if session:
        security.audit("logout", user_id=session["id"], ip=client_ip(request))
    if token:
        security.delete_session(token)
    response = redirect("/")
    response.delete_cookie(config.SESSION_COOKIE, path="/")
    return response


# ==========================================================================
#  Пароль: смена и восстановление
# ==========================================================================

@app.get("/password/change", response_class=HTMLResponse)
def password_change_form(request: Request, session=Depends(require_user)):
    return render(request, "change_password.html", forced=bool(session["must_change_password"]))


@app.post("/password/change", response_class=HTMLResponse)
def password_change(request: Request,
                    csrf_token: str = Form(...),
                    current_password: str = Form(...),
                    password: str = Form(...),
                    password_repeat: str = Form(...),
                    session=Depends(require_user)):
    check_csrf(request, csrf_token)

    if not security.verify_password(current_password, session["pwd_hash"],
                                    session["pwd_salt"], session["pwd_iters"]):
        return render(request, "change_password.html", errors=["Текущий пароль неверен."])

    error = security.validate_password(password)
    if error:
        return render(request, "change_password.html", errors=[error])
    if password != password_repeat:
        return render(request, "change_password.html", errors=["Пароли не совпадают."])

    security.change_password(session["id"], password)
    security.delete_all_sessions(session["id"])   # все прежние входы закрыты
    security.audit("password_changed", user_id=session["id"], ip=client_ip(request))

    response = redirect("/login")
    response.delete_cookie(config.SESSION_COOKIE, path="/")
    return response


@app.get("/password/reset", response_class=HTMLResponse)
def password_reset_request_form(request: Request):
    return render(request, "password_reset_request.html")


@app.post("/password/reset", response_class=HTMLResponse)
def password_reset_request(request: Request, email: str = Form(...)):
    ip = client_ip(request)
    if security.rate_limited("password_reset_request", ip):
        return render(request, "password_reset_request.html",
                      errors=["Слишком много запросов. Подождите минуту."])
    security.audit("password_reset_request", ip=ip, detail=email)

    user = security.find_user_by_email(email)
    if user is not None:
        token = threefa.create_reset_token(user["id"])
        link = str(request.base_url).rstrip("/") + f"/password/reset/{token}"
        mailer.send_reset_link(user["email"], link)

    # Ответ одинаков независимо от того, есть такой адрес или нет:
    # иначе форма превращается в проверялку зарегистрированных адресов.
    return render(request, "password_reset_request.html",
                  notice="Если адрес зарегистрирован, на него отправлено письмо со ссылкой.")


@app.get("/password/reset/{token}", response_class=HTMLResponse)
def password_reset_form(request: Request, token: str):
    return render(request, "password_reset.html", token=token)


@app.post("/password/reset/{token}", response_class=HTMLResponse)
def password_reset(request: Request, token: str,
                   password: str = Form(...),
                   password_repeat: str = Form(...)):
    error = security.validate_password(password)
    if error or password != password_repeat:
        return render(request, "password_reset.html", token=token,
                      errors=[error or "Пароли не совпадают."])

    user_id = threefa.consume_reset_token(token)
    if user_id is None:
        return render(request, "password_reset.html", token=token,
                      errors=["Ссылка недействительна или истекла."])

    security.change_password(user_id, password)
    security.delete_all_sessions(user_id)
    security.audit("password_reset_done", user_id=user_id, ip=client_ip(request))
    return render(request, "password_reset.html", done=True)


# ==========================================================================
#  Шифрование — то, ради чего существует вся система
# ==========================================================================

@app.get("/encrypt", response_class=HTMLResponse)
def encrypt_form(request: Request, session=Depends(require_user)):
    if session["must_change_password"]:
        return redirect("/password/change")
    return render(request, "encrypt.html", methods=db.enabled_methods(),
                  rsa_limit=_rsa_limit())


def _rsa_limit():
    try:
        return crypto.rsa_max_message_bytes()
    except OSError:
        return 0


@app.post("/encrypt", response_class=HTMLResponse)
def encrypt(request: Request,
            csrf_token: str = Form(...),
            method: str = Form(...),
            plaintext: str = Form(...),
            session=Depends(require_user)):
    check_csrf(request, csrf_token)

    methods = db.enabled_methods()
    # Повторная проверка на сервере: то, что форма предложила только
    # разрешённые варианты, ничего не гарантирует — POST можно послать свой.
    if method not in methods:
        raise HTTPException(status_code=403, detail="Этот метод отключён администратором")
    if not plaintext.strip():
        return render(request, "encrypt.html", methods=methods, rsa_limit=_rsa_limit(),
                      errors=["Введите текст сообщения."])

    data = plaintext.encode("utf-8")
    key_id = Path(config.RSA_KEY_PREFIX).name if method == "rsa" else "per-message"

    try:
        if method == "kuznyechik":
            # Свежий ключ и свежий IV на каждое сообщение. Повтор пары
            # (ключ, IV) выдал бы XOR двух открытых текстов.
            message_key = crypto.random_bytes(32)
            iv = crypto.random_bytes(8)
            ciphertext = crypto.kuznyechik_crypt(data, message_key, iv)

            # Ключ сообщения в базу кладётся только в обёртке мастер-ключа.
            wrapped, wrap_iv = crypto.wrap_key(message_key)
            row = (session["id"], method, ciphertext.hex(), iv.hex(),
                   wrapped.hex(), wrap_iv.hex(), key_id, security.stamp())
        else:
            limit = crypto.rsa_max_message_bytes()
            if len(data) > limit:
                return render(request, "encrypt.html", methods=methods, rsa_limit=limit,
                              errors=[f"Для RSA сообщение не длиннее {limit} байт "
                                      f"(введено {len(data)})."])
            ciphertext = crypto.rsa_encrypt(data)
            row = (session["id"], method, ciphertext.hex(), None, None, None,
                   key_id, security.stamp())

    except crypto.CryptoError as error:
        return render(request, "encrypt.html", methods=methods, rsa_limit=_rsa_limit(),
                      errors=[f"Ошибка криптографического слоя: {error}"])

    with db.connect() as connection:
        cursor = connection.execute(
            "INSERT INTO messages(user_id, method, ciphertext_hex, iv_hex, "
            "wrapped_key_hex, wrap_iv_hex, key_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", row)
        message_id = cursor.lastrowid

    security.audit("encrypt", user_id=session["id"], ip=client_ip(request),
                   detail=f"{method}, сообщение {message_id}")
    return redirect(f"/history/{message_id}")


# ==========================================================================
#  История
# ==========================================================================

@app.get("/history", response_class=HTMLResponse)
def history(request: Request, session=Depends(require_user)):
    # Выборка ограничена user_id из СЕССИИ. Если взять его из URL,
    # пользователь 7 прочитает переписку пользователя 8, поправив адрес.
    with db.connect() as connection:
        rows = connection.execute(
            "SELECT id, method, ciphertext_hex, created_at FROM messages "
            "WHERE user_id = ? ORDER BY id DESC", (session["id"],)).fetchall()
    return render(request, "history.html", messages=rows)


def _load_message(message_id: int, session):
    """
    Сообщение, если оно принадлежит пользователю либо запрашивает админ.
    Возвращает (строка сообщения, имя владельца).
    """
    with db.connect() as connection:
        row = connection.execute(
            "SELECT m.*, u.username FROM messages m JOIN users u ON u.id = m.user_id "
            "WHERE m.id = ?", (message_id,)).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Сообщение не найдено")
    if row["user_id"] != session["id"] and session["role"] != "admin":
        # 404, а не 403: иначе по коду ответа видно, какие номера существуют.
        raise HTTPException(status_code=404, detail="Сообщение не найдено")
    return row, row["username"]


def _decrypt(row) -> str:
    """
    Расшифровывает сообщение по требованию.

    Открытого текста в базе нет сознательно: система, хранящая все
    сообщения в открытом виде, обессмысливает собственное шифрование.
    """
    ciphertext = bytes.fromhex(row["ciphertext_hex"])
    if row["method"] == "kuznyechik":
        message_key = crypto.unwrap_key(bytes.fromhex(row["wrapped_key_hex"]),
                                        bytes.fromhex(row["wrap_iv_hex"]))
        data = crypto.kuznyechik_crypt(ciphertext, message_key, bytes.fromhex(row["iv_hex"]))
    else:
        data = crypto.rsa_decrypt(ciphertext)
    return data.decode("utf-8", errors="replace")


@app.get("/history/{message_id}", response_class=HTMLResponse)
def message_detail(request: Request, message_id: int, session=Depends(require_user)):
    row, owner = _load_message(message_id, session)
    try:
        plaintext = _decrypt(row)
        error = None
    except crypto.CryptoError as failure:
        plaintext, error = "", str(failure)
    return render(request, "message.html", message=row, owner=owner,
                  plaintext=plaintext, error=error)


@app.get("/history/{message_id}/pdf")
def message_pdf(request: Request, message_id: int, session=Depends(require_user)):
    row, owner = _load_message(message_id, session)
    pdf_path, _ = documents.pdf_and_signature(row, owner, _decrypt(row))
    security.audit("pdf_export", user_id=session["id"], ip=client_ip(request),
                   detail=f"сообщение {message_id}")
    return FileResponse(pdf_path, media_type="application/pdf",
                        filename=f"message-{message_id}.pdf")


@app.get("/history/{message_id}/pdf.sig")
def message_signature(request: Request, message_id: int, session=Depends(require_user)):
    row, owner = _load_message(message_id, session)
    _, sig_path = documents.pdf_and_signature(row, owner, _decrypt(row))
    return FileResponse(sig_path, media_type="text/plain",
                        filename=f"message-{message_id}.pdf.sig")


# ==========================================================================
#  Проверка подписи
#
#  Открытая страница: подпись проверяется открытым ключом, секретов для
#  этого не нужно. Подпись, которую никто не может проверить, —
#  это украшение, а не подпись.
# ==========================================================================

@app.get("/verify", response_class=HTMLResponse)
def verify_form(request: Request):
    return render(request, "verify.html", rsa_bits=_rsa_bits_or_none())


@app.post("/verify", response_class=HTMLResponse)
async def verify(request: Request, document: UploadFile, signature: UploadFile):
    document_bytes = await document.read()
    signature_text = (await signature.read()).decode("ascii", errors="replace")

    valid, explanation = documents.verify_uploaded(document_bytes, signature_text)
    security.audit("signature_verify", ip=client_ip(request),
                   detail=f"{document.filename}: {'OK' if valid else 'FAIL'}")
    return render(request, "verify.html", rsa_bits=_rsa_bits_or_none(),
                  result=valid, explanation=explanation, filename=document.filename)


# ==========================================================================
#  Панель администратора
# ==========================================================================

@app.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request, session=Depends(require_admin)):
    with db.connect() as connection:
        users = connection.execute(
            "SELECT id, username, email, role, is_active, created_at, locked_until "
            "FROM users ORDER BY id").fetchall()
        recent = connection.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT 40").fetchall()
    return render(request, "admin.html", users=users, recent=recent,
                  kuz_enabled=db.get_setting("kuz_enabled") == "1",
                  rsa_enabled=db.get_setting("rsa_enabled") == "1")


@app.post("/admin/methods")
def admin_methods(request: Request,
                  csrf_token: str = Form(...),
                  kuz_enabled: str = Form("0"),
                  rsa_enabled: str = Form("0"),
                  session=Depends(require_admin)):
    check_csrf(request, csrf_token)
    db.set_setting("kuz_enabled", "1" if kuz_enabled == "1" else "0")
    db.set_setting("rsa_enabled", "1" if rsa_enabled == "1" else "0")
    security.audit("admin_methods", user_id=session["id"], ip=client_ip(request),
                   detail=f"kuz={kuz_enabled} rsa={rsa_enabled}")
    return redirect("/admin")


@app.get("/admin/messages", response_class=HTMLResponse)
def admin_messages(request: Request, session=Depends(require_admin)):
    # Та же выборка, что в истории пользователя, но без фильтра по user_id
    # и с колонкой владельца.
    with db.connect() as connection:
        rows = connection.execute(
            "SELECT m.id, m.method, m.ciphertext_hex, m.created_at, u.username "
            "FROM messages m JOIN users u ON u.id = m.user_id ORDER BY m.id DESC").fetchall()
    return render(request, "admin_messages.html", messages=rows)


@app.post("/admin/users", response_class=HTMLResponse)
def admin_create_user(request: Request,
                      csrf_token: str = Form(...),
                      username: str = Form(...),
                      email: str = Form(...),
                      role: str = Form(...),
                      session=Depends(require_admin)):
    check_csrf(request, csrf_token)

    errors = [error for error in (security.validate_username(username),
                                  security.validate_email(email)) if error]
    if role not in ("user", "admin"):
        errors.append("Неизвестная роль.")
    if errors:
        return redirect("/admin?error=" + "+".join(errors))

    # Начальный пароль случаен, показывается один раз и обязателен к смене.
    initial_password = crypto.random_bytes(9).hex() + "Aa1!"
    secret = threefa.new_totp_secret()
    try:
        user_id = security.create_user(username, email, initial_password, role, secret,
                                       must_change_password=True)
    except sqlite3.IntegrityError:
        return redirect("/admin?error=Имя+или+адрес+уже+заняты")

    codes = threefa.create_recovery_codes(user_id)
    security.audit("admin_create_user", user_id=session["id"], ip=client_ip(request),
                   detail=f"{username} ({role})")

    return render(request, "register_done.html",
                  username=username,
                  codes=codes,
                  totp_secret=secret,
                  initial_password=initial_password,
                  qr_data_uri=_qr_data_uri(threefa.totp_uri(username, secret)))


@app.post("/admin/users/{user_id}/toggle")
def admin_toggle_user(request: Request, user_id: int,
                      csrf_token: str = Form(...),
                      session=Depends(require_admin)):
    check_csrf(request, csrf_token)
    if user_id == session["id"]:
        raise HTTPException(status_code=400, detail="Нельзя отключить себя")

    with db.connect() as connection:
        connection.execute(
            "UPDATE users SET is_active = 1 - is_active WHERE id = ?", (user_id,))
    security.delete_all_sessions(user_id)
    security.audit("admin_toggle_user", user_id=session["id"], ip=client_ip(request),
                   detail=f"пользователь {user_id}")
    return redirect("/admin")


# ==========================================================================
#  Обработка ошибок
# ==========================================================================

@app.exception_handler(HTTPException)
def http_error(request: Request, error: HTTPException):
    # Зависимость require_user сообщает «нужен вход» кодом 303 с Location.
    if error.status_code == 303 and "Location" in (error.headers or {}):
        return redirect(error.headers["Location"])
    return templates.TemplateResponse(
        request, "error.html",
        {"code": error.status_code, "detail": error.detail, "title": config.APP_TITLE,
         "user": None, "csrf_token": ""},
        status_code=error.status_code)
