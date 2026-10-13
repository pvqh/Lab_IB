"""
Шов между Python и C++ — единственный модуль, который знает о crypto_cli.

Весь обмен устроен так:

    subprocess.run([...])  ->  код 0 и hex в stdout, либо код != 0 и текст
                               ошибки в stderr

Поэтому обработка ошибок одинакова в каждом вызове и занимает три строки
(см. _run). Никакого разбора вывода нет: stdout содержит только результат.

Почему процесс, а не DLL. Через ctypes нельзя передать BigInt — это класс
C++ с std::vector внутри, и Python не умеет его ни создать, ни освободить.
Пришлось бы писать плоскую C-обёртку, которая всё равно обменивалась бы
hex-строками, но уже с ручным управлением памятью. Вдобавок изоляция
процесса — это свойство безопасности: падение или ошибка работы с памятью
в C++ убивает отдельный процесс и не портит адресное пространство
веб-сервера, где лежат сессии.
"""

import re
import secrets
import subprocess
import tempfile
from pathlib import Path

import config


class CryptoError(RuntimeError):
    """crypto_cli завершился с ненулевым кодом."""


# --------------------------------------------------------------------------
# Запуск crypto_cli
# --------------------------------------------------------------------------

def _to_cli_path(path) -> str:
    """
    Путь в том виде, в котором его поймёт crypto_cli.

    При запуске через WSL исполняется Linux-бинарник, и путь C:\\Users\\...
    для него не существует — его надо записать как /mnt/c/Users/...
    При прямом запуске путь отдаётся как есть.
    """
    text = str(Path(path).resolve())
    if config.CRYPTO_CLI_LAUNCHER != "wsl":
        return text

    match = re.match(r"^([A-Za-z]):[\\/](.*)$", text)
    if not match:
        return text.replace("\\", "/")
    drive, rest = match.groups()
    return f"/mnt/{drive.lower()}/" + rest.replace("\\", "/")


def _run(subcommand: str, *args: str) -> str:
    """
    Вызывает crypto_cli и возвращает содержимое stdout без перевода строки.

    Единая точка обработки ошибок: ненулевой код возврата превращается
    в исключение с текстом из stderr.
    """
    command = []
    if config.CRYPTO_CLI_LAUNCHER == "wsl":
        command += ["wsl.exe", "-d", config.WSL_DISTRO, "--"]
    command += [_to_cli_path(config.CRYPTO_CLI) if config.CRYPTO_CLI_LAUNCHER == "wsl"
                else config.CRYPTO_CLI, subcommand, *args]

    result = subprocess.run(command, capture_output=True)
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise CryptoError(f"crypto_cli {subcommand}: {message or 'код ' + str(result.returncode)}")
    return result.stdout.decode("ascii", errors="replace").strip()


def _temp_dir():
    """
    Временный каталог для файлов, которые читает crypto_cli.

    Лежит внутри проекта, а не в системном %TEMP%, по двум причинам:
    путь должен быть виден и из Windows, и из WSL, и видно, что ничего
    не осталось после работы.
    """
    config.TMP_DIR.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=config.TMP_DIR)


# --------------------------------------------------------------------------
# Случайные данные
#
# Берутся прямо из Python: secrets использует системный генератор (тот же,
# что crypto_cli random), а лишний запуск процесса стоит полсекунды.
# Подкоманда random остаётся для shell-тестов.
# --------------------------------------------------------------------------

def random_bytes(count: int) -> bytes:
    return secrets.token_bytes(count)


# --------------------------------------------------------------------------
# «Кузнечик» в режиме CTR
# --------------------------------------------------------------------------

def kuznyechik_crypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Шифрует ИЛИ расшифровывает данные — в CTR это одна и та же операция
    (XOR с гаммой), поэтому отдельной функции для расшифрования нет.

    @param key 32 байта
    @param iv  8 байт, уникальные для каждого сообщения
    """
    if len(key) != 32:
        raise ValueError("ключ «Кузнечика» должен быть 32 байта")
    if len(iv) != 8:
        raise ValueError("IV должен быть 8 байт")

    with _temp_dir() as folder:
        source = Path(folder) / "in.bin"
        target = Path(folder) / "out.bin"
        source.write_bytes(data)
        _run("kuz-encrypt",
             "--key", key.hex(), "--iv", iv.hex(),
             "--in", _to_cli_path(source), "--out", _to_cli_path(target))
        return target.read_bytes()


# --------------------------------------------------------------------------
# Стрибог
# --------------------------------------------------------------------------

def stribog(data: bytes, bits: int = 512) -> bytes:
    with _temp_dir() as folder:
        source = Path(folder) / "in.bin"
        source.write_bytes(data)
        return bytes.fromhex(_run("stribog", "--bits", str(bits), "--in", _to_cli_path(source)))


def kdf(password: str, salt: bytes, iterations: int) -> bytes:
    """
    Хеш пароля: Стрибог с солью, повторённый iterations раз.

    Цикл выполняется внутри C++ одним вызовом процесса. Если бы итерации
    крутил Python, каждая стоила бы запуск процесса — часы вместо
    долей секунды.
    """
    with _temp_dir() as folder:
        source = Path(folder) / "password.bin"
        source.write_bytes(password.encode("utf-8"))
        return bytes.fromhex(_run("kdf",
                                  "--salt", salt.hex(),
                                  "--password-file", _to_cli_path(source),
                                  "--iterations", str(iterations)))


# --------------------------------------------------------------------------
# RSA
# --------------------------------------------------------------------------

def _rsa_key_file(extension: str) -> str:
    path = Path(config.RSA_KEY_PREFIX + extension)
    if not path.exists():
        raise CryptoError(
            f"нет файла ключа RSA: {path}\n"
            f"создайте его:  crypto_cli rsa-keygen --bits 2048 "
            f"--out-prefix {config.RSA_KEY_PREFIX}")
    return _to_cli_path(path)


def rsa_modulus_bits() -> int:
    """Размер модуля в битах — по длине hex-записи n."""
    hex_text = Path(config.RSA_KEY_PREFIX + ".n").read_text(encoding="ascii").strip()
    return len(hex_text) * 4


def rsa_max_message_bytes() -> int:
    """Сколько байт влезает в один блок RSA (один байт уходит на маркер)."""
    return rsa_modulus_bits() // 8 - 1


def rsa_encrypt(data: bytes) -> bytes:
    with _temp_dir() as folder:
        source = Path(folder) / "in.bin"
        target = Path(folder) / "out.bin"
        source.write_bytes(data)
        _run("rsa-encrypt",
             "--n", _rsa_key_file(".n"), "--e", _rsa_key_file(".e"),
             "--in", _to_cli_path(source), "--out", _to_cli_path(target))
        return target.read_bytes()


def rsa_decrypt(data: bytes) -> bytes:
    with _temp_dir() as folder:
        source = Path(folder) / "in.bin"
        target = Path(folder) / "out.bin"
        source.write_bytes(data)
        _run("rsa-decrypt",
             "--n", _rsa_key_file(".n"), "--d", _rsa_key_file(".d"),
             "--in", _to_cli_path(source), "--out", _to_cli_path(target))
        return target.read_bytes()


def rsa_sign(document: bytes) -> bytes:
    """ЭЦП: подписывается хеш документа, а не сам документ."""
    with _temp_dir() as folder:
        source = Path(folder) / "doc.bin"
        source.write_bytes(document)
        return bytes.fromhex(_run("rsa-sign",
                                  "--n", _rsa_key_file(".n"), "--d", _rsa_key_file(".d"),
                                  "--in", _to_cli_path(source)))


def rsa_verify(document: bytes, signature: bytes) -> bool:
    """True, если подпись соответствует документу. Неверная подпись — не ошибка."""
    with _temp_dir() as folder:
        source = Path(folder) / "doc.bin"
        sig_file = Path(folder) / "doc.sig"
        source.write_bytes(document)
        sig_file.write_text(signature.hex(), encoding="ascii")
        try:
            _run("rsa-verify",
                 "--n", _rsa_key_file(".n"), "--e", _rsa_key_file(".e"),
                 "--in", _to_cli_path(source), "--sig", _to_cli_path(sig_file))
            return True
        except CryptoError:
            return False


# --------------------------------------------------------------------------
# Конвертное шифрование (envelope encryption)
#
# Ключ сообщения случаен и используется один раз. В базе он лежит не
# открытым, а зашифрованным мастер-ключом сервера, который хранится в файле
# вне каталога приложения. Поэтому украденной базы недостаточно: без файла
# мастер-ключа ни одно сообщение не расшифровывается.
#
# Мастер-ключ шифрует ключ сообщения тем же «Кузнечиком». IV здесь берётся
# свой, случайный, и хранится рядом — повторять пару (ключ, IV) нельзя
# и на этом уровне.
# --------------------------------------------------------------------------

def wrap_key(message_key: bytes) -> tuple[bytes, bytes]:
    """Зашифровать ключ сообщения мастер-ключом. Возвращает (обёртка, IV)."""
    iv = random_bytes(8)
    return kuznyechik_crypt(message_key, config.master_key(), iv), iv


def unwrap_key(wrapped: bytes, iv: bytes) -> bytes:
    """Обратная операция к wrap_key."""
    return kuznyechik_crypt(wrapped, config.master_key(), iv)
