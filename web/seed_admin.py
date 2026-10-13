"""
Создание первого администратора.

Это отдельный скрипт, а не веб-маршрут, и так и должно быть: открытый
маршрут «сделай меня администратором», который забыли удалить перед
сдачей, — это полная компрометация системы и любимый вопрос на защите.
Скрипт запускается с консоли сервера, то есть требует доступа к машине.

Запуск:
    python seed_admin.py admin admin@example.com "ПарольПосложнее1!"

Если пароль не указан, он генерируется случайно и печатается один раз.
"""

import sys

import config
import crypto
import db
import security
import threefa


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2

    username, email = argv[1], argv[2]
    password = argv[3] if len(argv) > 3 else crypto.random_bytes(9).hex() + "Aa1!"

    config.ensure_directories()
    db.init()

    for value, check in ((username, security.validate_username),
                         (email, security.validate_email),
                         (password, security.validate_password)):
        error = check(value)
        if error:
            print("Ошибка:", error)
            return 1

    if security.find_user(username) is not None:
        print(f"Пользователь {username} уже существует.")
        return 1

    secret = threefa.new_totp_secret()
    user_id = security.create_user(username, email, password, "admin", secret)
    codes = threefa.create_recovery_codes(user_id)

    print(f"Администратор создан: {username} (id {user_id})")
    print(f"Пароль:        {password}")
    print(f"Секрет TOTP:   {secret}")
    print("Коды восстановления (показываются один раз):")
    for code in codes:
        print("   ", code)
    print()
    print("Секрет TOTP добавьте в приложение-аутентификатор вручную")
    print("или по ссылке:", threefa.totp_uri(username, secret))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
