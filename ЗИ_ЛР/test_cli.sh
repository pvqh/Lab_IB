#!/usr/bin/env bash
#
# Сквозная проверка контракта crypto_cli: каждая подкоманда вызывается так же,
# как её вызывает Python, и результат сверяется побайтно.
#
# Это регрессионный тест границы между C++ и Python. Если он зелёный, то
# ошибку надо искать в веб-приложении, а не в криптографии.
#
# Запуск:  ./test_cli.sh [путь-к-ключу-RSA-без-расширения]
# По умолчанию берётся key_dev (быстрый), а не key_32768.

set -u
cd "$(dirname "$0")"

CLI=./crypto_cli
KEY=${1:-key_dev}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

passed=0
failed=0

ok()   { echo "  OK   $1"; passed=$((passed + 1)); }
bad()  { echo "  FAIL $1"; failed=$((failed + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (получено '$2', ожидалось '$3')"; fi; }

echo "crypto_cli: сквозная проверка"
echo

# --------------------------------------------------------------------------
echo "Коды возврата и потоки"

# stdout должен содержать ТОЛЬКО результат: ровно одну строку.
lines=$($CLI random --bytes 32 2>/dev/null | wc -l)
check "random: одна строка в stdout" "$lines" "1"

hexlen=$($CLI random --bytes 32 2>/dev/null | tr -d '\n' | wc -c)
check "random: 32 байта = 64 hex-цифры" "$hexlen" "64"

# Два вызова не должны совпасть — иначе генератор не случайный.
if [ "$($CLI random --bytes 16)" != "$($CLI random --bytes 16)" ]; then
    ok "random: два вызова различаются"
else
    bad "random: два вызова совпали"
fi

$CLI no-such-command >/dev/null 2>&1
check "неизвестная команда -> код 2" "$?" "2"

$CLI stribog --bits 512 --in /no/such/file >/dev/null 2>&1
check "отсутствующий файл -> код 1" "$?" "1"

# Ошибка обязана идти в stderr, а не в stdout.
out=$($CLI stribog --in /no/such/file 2>/dev/null)
check "ошибка не попадает в stdout" "$out" ""

echo

# --------------------------------------------------------------------------
echo "Кузнечик в режиме CTR"

# Данные специально не кратны 16 байтам.
head -c 1000 /dev/urandom > "$TMP/plain.bin"
KUZKEY=$($CLI random --bytes 32)
IV=$($CLI random --bytes 8)

$CLI kuz-encrypt --key "$KUZKEY" --iv "$IV" --in "$TMP/plain.bin" --out "$TMP/ct.bin"
check "шифрование завершилось кодом 0" "$?" "0"

check "длина шифртекста равна длине текста" \
      "$(wc -c < "$TMP/ct.bin")" "$(wc -c < "$TMP/plain.bin")"

if cmp -s "$TMP/plain.bin" "$TMP/ct.bin"; then
    bad "шифртекст совпал с открытым текстом"
else
    ok "шифртекст отличается от открытого текста"
fi

$CLI kuz-decrypt --key "$KUZKEY" --iv "$IV" --in "$TMP/ct.bin" --out "$TMP/back.bin"
if cmp -s "$TMP/plain.bin" "$TMP/back.bin"; then
    ok "круговой прогон: расшифровано верно"
else
    bad "круговой прогон: расшифровано неверно"
fi

# Неверный ключ не должен давать исходные данные.
WRONGKEY=$($CLI random --bytes 32)
$CLI kuz-decrypt --key "$WRONGKEY" --iv "$IV" --in "$TMP/ct.bin" --out "$TMP/wrong.bin"
if cmp -s "$TMP/plain.bin" "$TMP/wrong.bin"; then
    bad "неверный ключ расшифровал данные"
else
    ok "неверный ключ даёт мусор"
fi

# Ключ и IV неверной длины должны отвергаться, а не молча обрезаться.
$CLI kuz-encrypt --key "aabb" --iv "$IV" --in "$TMP/plain.bin" --out "$TMP/x.bin" 2>/dev/null
check "короткий ключ отвергнут" "$?" "1"
$CLI kuz-encrypt --key "$KUZKEY" --iv "aa" --in "$TMP/plain.bin" --out "$TMP/x.bin" 2>/dev/null
check "короткий IV отвергнут" "$?" "1"

echo

# --------------------------------------------------------------------------
echo "Стрибог"

printf 'abc' > "$TMP/abc.txt"
h1=$($CLI stribog --bits 512 --in "$TMP/abc.txt")
h2=$($CLI stribog --bits 512 --in "$TMP/abc.txt")
check "хеш детерминирован" "$h1" "$h2"
check "512 бит = 128 hex-цифр" "${#h1}" "128"
h256=$($CLI stribog --bits 256 --in "$TMP/abc.txt")
check "256 бит = 64 hex-цифры" "${#h256}" "64"

printf 'abd' > "$TMP/abd.txt"
if [ "$($CLI stribog --in "$TMP/abd.txt")" != "$h1" ]; then
    ok "разные данные дают разный хеш"
else
    bad "разные данные дали одинаковый хеш"
fi

# Файл больше одного блока (64 байта) — проверка многоблочного режима.
head -c 5000 /dev/urandom > "$TMP/big.bin"
big=$($CLI stribog --bits 512 --in "$TMP/big.bin")
check "хеш файла в 5000 байт считается" "${#big}" "128"

echo

# --------------------------------------------------------------------------
echo "KDF (хеширование паролей)"

printf 'correct horse battery staple' > "$TMP/pw.txt"
SALT=$($CLI random --bytes 16)
k1=$($CLI kdf --salt "$SALT" --password-file "$TMP/pw.txt" --iterations 200)
k2=$($CLI kdf --salt "$SALT" --password-file "$TMP/pw.txt" --iterations 200)
check "одинаковые вход и соль -> одинаковый хеш" "$k1" "$k2"
check "длина хеша 512 бит" "${#k1}" "128"

SALT2=$($CLI random --bytes 16)
if [ "$($CLI kdf --salt "$SALT2" --password-file "$TMP/pw.txt" --iterations 200)" != "$k1" ]; then
    ok "другая соль -> другой хеш"
else
    bad "соль не влияет на результат"
fi

if [ "$($CLI kdf --salt "$SALT" --password-file "$TMP/pw.txt" --iterations 201)" != "$k1" ]; then
    ok "другое число итераций -> другой хеш"
else
    bad "число итераций не влияет на результат"
fi

echo

# --------------------------------------------------------------------------
echo "RSA (ключ: $KEY)"

if [ ! -f "$KEY.n" ]; then
    echo "  ПРОПУЩЕНО: нет файла $KEY.n."
    echo "  Создайте ключ:  $CLI rsa-keygen --bits 2048 --out-prefix $KEY"
else
    bits=$(( $(tr -d '\n' < "$KEY.n" | wc -c) * 4 ))
    echo "  (модуль примерно $bits бит)"

    printf 'Атака на рассвете' > "$TMP/msg.bin"

    $CLI rsa-encrypt --n "$KEY.n" --e "$KEY.e" --in "$TMP/msg.bin" --out "$TMP/msg.rsa"
    check "шифрование завершилось кодом 0" "$?" "0"

    if cmp -s "$TMP/msg.bin" "$TMP/msg.rsa"; then
        bad "шифртекст совпал с открытым текстом"
    else
        ok "шифртекст отличается от открытого текста"
    fi

    $CLI rsa-decrypt --n "$KEY.n" --d "$KEY.d" --in "$TMP/msg.rsa" --out "$TMP/msg.back"
    if cmp -s "$TMP/msg.bin" "$TMP/msg.back"; then
        ok "круговой прогон: расшифровано верно"
    else
        bad "круговой прогон: расшифровано неверно"
    fi

    # Сообщение длиннее блока обязано быть отвергнуто, а не обрезано.
    head -c 100000 /dev/zero > "$TMP/toolong.bin"
    $CLI rsa-encrypt --n "$KEY.n" --e "$KEY.e" --in "$TMP/toolong.bin" --out "$TMP/x.rsa" 2>/dev/null
    check "слишком длинное сообщение отвергнуто" "$?" "1"

    # --- ЭЦП ---
    $CLI rsa-sign --n "$KEY.n" --d "$KEY.d" --in "$TMP/big.bin" > "$TMP/big.sig"
    check "подпись создана" "$?" "0"

    $CLI rsa-verify --n "$KEY.n" --e "$KEY.e" --in "$TMP/big.bin" --sig "$TMP/big.sig" >/dev/null
    check "подпись проверяется (код 0)" "$?" "0"

    # Меняем один байт документа — подпись обязана перестать проходить.
    cp "$TMP/big.bin" "$TMP/tampered.bin"
    printf 'X' | dd of="$TMP/tampered.bin" bs=1 seek=100 conv=notrunc status=none
    $CLI rsa-verify --n "$KEY.n" --e "$KEY.e" --in "$TMP/tampered.bin" --sig "$TMP/big.sig" >/dev/null
    check "подделанный документ отвергнут (код 1)" "$?" "1"

    # Меняем подпись — тоже обязана перестать проходить.
    sed 's/^./f/' "$TMP/big.sig" > "$TMP/bad.sig"
    $CLI rsa-verify --n "$KEY.n" --e "$KEY.e" --in "$TMP/big.bin" --sig "$TMP/bad.sig" >/dev/null 2>&1
    check "подделанная подпись отвергнута" "$?" "1"
fi

echo
echo "итого: пройдено $passed, провалено $failed"
[ "$failed" -eq 0 ]
