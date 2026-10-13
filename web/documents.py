"""
PDF-отчёт по сообщению и электронная подпись к нему.

Схема подписи складывается из двух уже готовых примитивов:

    подпись  = RSA_d( Стрибог512(байты документа) )
    проверка: RSA_e( подпись ) == Стрибог512(байты документа)

Подписывается хеш, а не сам документ: документ в мегабайты не влезет
в один блок RSA, да и возведение в степень по модулю 32768 бит для
каждого блока было бы недопустимо медленным.

────────────────────────────────────────────────────────────────────────
Ловушка, из-за которой подпись «внутри PDF» не работает

Если положить подпись в сам PDF, байты файла изменятся, вместе с ними
изменится хеш — и подпись перестанет соответствовать документу. Поэтому
подпись лежит ОТДЕЛЬНЫМ файлом (sidecar): рядом с report.pdf выдаётся
report.pdf.sig, и подписаны ровно те байты PDF, которые скачал
пользователь.

Отсюда второе решение: готовый PDF и его подпись сохраняются на диск
и при повторных скачиваниях выдаются те же самые байты. Если
генерировать PDF заново на каждый запрос, в него попадёт новая дата
создания, байты разойдутся, и подпись к скачанному ранее файлу
перестанет проходить проверку. Плюс подпись ключом на 32768 бит
занимает около 16 секунд — делать её дважды незачем.
────────────────────────────────────────────────────────────────────────
"""

import os
from datetime import datetime
from pathlib import Path

from fpdf import FPDF

import config
import crypto

PDF_DIR = config.VAR_DIR / "pdf"


def _font_path() -> str:
    """Первый найденный TTF с кириллицей: встроенные шрифты fpdf2 её не содержат."""
    for candidate in config.PDF_FONT_CANDIDATES:
        if candidate and os.path.exists(candidate):
            return candidate
    raise RuntimeError(
        "не найден шрифт с кириллицей. Укажите путь к .ttf в переменной PDF_FONT, "
        "например PDF_FONT=C:/Windows/Fonts/arial.ttf")


def _wrap_hex(hex_text: str, per_line: int = 64) -> str:
    """Длинный hex переносим сами: иначе строка уедет за край страницы."""
    return "\n".join(hex_text[i:i + per_line] for i in range(0, len(hex_text), per_line))


def build_pdf(message, username: str, plaintext: str) -> bytes:
    """Собирает отчёт по одному сообщению и возвращает байты PDF."""
    pdf = FPDF()
    pdf.add_font("body", "", _font_path())
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("body", size=16)
    pdf.cell(0, 10, "Отчёт о зашифрованном сообщении", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    method_names = {"kuznyechik": "Кузнечик (ГОСТ Р 34.12-2015), режим CTR",
                    "rsa": "RSA (учебная схема, без заполнения)"}

    pdf.set_font("body", size=11)
    for label, value in [
        ("Пользователь", username),
        ("Дата и время (UTC)", message["created_at"]),
        ("Метод шифрования", method_names.get(message["method"], message["method"])),
        ("Идентификатор ключа", message["key_id"]),
    ]:
        pdf.cell(55, 7, label + ":")
        pdf.cell(0, 7, str(value), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.set_font("body", size=13)
    pdf.cell(0, 8, "Исходный текст", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("body", size=11)
    pdf.multi_cell(0, 6, plaintext)

    pdf.ln(3)
    pdf.set_font("body", size=13)
    pdf.cell(0, 8, "Шифртекст (hex)", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("body", size=8)
    pdf.multi_cell(0, 4, _wrap_hex(message["ciphertext_hex"]))

    if message["iv_hex"]:
        pdf.ln(2)
        pdf.set_font("body", size=11)
        pdf.cell(0, 6, "IV (синхропосылка): " + message["iv_hex"],
                 new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.set_font("body", size=9)
    pdf.multi_cell(0, 5,
                   "Электронная подпись этого файла находится в отдельном файле "
                   "с расширением .sig. Подписан хеш Стрибог-512 от байтов данного "
                   "PDF, подпись выполнена закрытым ключом RSA. Проверить можно "
                   "на странице «Проверка подписи».")

    # Дата создания берётся из записи, а не из часов: повторная сборка
    # того же сообщения даёт те же байты, а значит и ту же подпись.
    pdf.set_creation_date(datetime.fromisoformat(message["created_at"]))
    return bytes(pdf.output())


def pdf_and_signature(message, username: str, plaintext: str) -> tuple[Path, Path]:
    """
    Возвращает пути к PDF и к файлу подписи, создавая их при первом вызове.

    Кеш на диске нужен для корректности, а не только для скорости:
    подпись должна относиться ровно к тем байтам, которые скачал
    пользователь.
    """
    PDF_DIR.mkdir(parents=True, exist_ok=True)
    pdf_path = PDF_DIR / f"message-{message['id']}.pdf"
    sig_path = PDF_DIR / f"message-{message['id']}.pdf.sig"

    if not (pdf_path.exists() and sig_path.exists()):
        pdf_bytes = build_pdf(message, username, plaintext)
        pdf_path.write_bytes(pdf_bytes)
        sig_path.write_text(crypto.rsa_sign(pdf_bytes).hex(), encoding="ascii")

    return pdf_path, sig_path


def verify_uploaded(document: bytes, signature_text: str) -> tuple[bool, str]:
    """
    Проверяет подпись загруженной пары файлов.

    Возвращает (результат, пояснение). Пояснение показывается на странице,
    чтобы было видно, что именно сравнивалось.
    """
    cleaned = "".join(signature_text.split())
    try:
        signature = bytes.fromhex(cleaned)
    except ValueError:
        return False, "Файл подписи не является шестнадцатеричным числом."

    digest = crypto.stribog(document, 512).hex()
    valid = crypto.rsa_verify(document, signature)
    explanation = (f"Стрибог-512 от документа: {digest}\n"
                   f"Размер документа: {len(document)} байт\n"
                   f"Размер подписи: {len(signature)} байт "
                   f"({crypto.rsa_modulus_bits()}-битный модуль)")
    return valid, explanation
