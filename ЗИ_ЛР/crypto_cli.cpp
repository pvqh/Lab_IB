/*
 * crypto_cli — единственная точка входа в криптографию для веб-приложения.
 *
 * Контракт (он же — вся граница между C++ и Python):
 *
 *   stdout      только результат, одна строка hex, без украшений
 *   stderr      ошибки, предупреждения, трассировка
 *   код 0       успех
 *   код != 0    неуспех
 *
 * Эта дисциплина позволяет обработке ошибок в Python быть одинаковой
 * в каждом вызове: если returncode != 0 — бросаем исключение с текстом
 * stderr, иначе читаем stdout. Больше ничего парсить не нужно.
 *
 * Мелкие данные фиксированной длины (ключи, IV, хеши, подписи) ходят
 * как hex в аргументах и в stdout. Данные произвольной длины ходят
 * через файлы: командная строка ограничена по длине, а двоичные байты
 * в ней всё равно не выживут.
 */

#include <cctype>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "BigInt.h"
#include "cryptography.h"
#include "kuz_ctr.h"

/* ========================================================================= *
 *  Разбор аргументов
 *
 *  Все аргументы имеют вид  --имя значение,  кроме --verbose (просто флаг).
 *  Восьми подкомандам этого хватает с запасом; библиотека разбора заняла бы
 *  больше места, чем сам разбор.
 * ========================================================================= */

class Args {
public:
    Args(int argc, char* argv[], int firstIndex) {
        for (int i = firstIndex; i < argc; ++i) {
            std::string token = argv[i];
            if (token.rfind("--", 0) != 0) {
                throw std::invalid_argument("ожидался флаг вида --имя, получено: " + token);
            }
            std::string name = token.substr(2);
            // Следующий токен — значение, если он есть и сам не флаг.
            if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
                values[name] = argv[++i];
            } else {
                values[name] = "";          // флаг без значения, например --verbose
            }
        }
    }

    bool has(const std::string& name) const { return values.count(name) > 0; }

    std::string require(const std::string& name) const {
        auto it = values.find(name);
        if (it == values.end() || it->second.empty()) {
            throw std::invalid_argument("не задан обязательный аргумент --" + name);
        }
        return it->second;
    }

    std::string optional(const std::string& name, const std::string& fallback) const {
        auto it = values.find(name);
        return (it == values.end() || it->second.empty()) ? fallback : it->second;
    }

private:
    std::map<std::string, std::string> values;
};

/* ========================================================================= *
 *  Файлы
 * ========================================================================= */

static std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("не удалось открыть файл: " + path);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file),
                                std::istreambuf_iterator<char>());
}

static void writeFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("не удалось создать файл: " + path);
    if (!data.empty()) file.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (!file) throw std::runtime_error("ошибка записи в файл: " + path);
}

/** Читает файл с одним hex-числом (ключи RSA, подписи), отбрасывая пробелы. */
static std::string readHexFile(const std::string& path) {
    std::vector<uint8_t> raw = readFile(path);
    std::string hex;
    for (uint8_t c : raw) {
        if (!std::isspace(c)) hex += static_cast<char>(c);
    }
    if (hex.empty()) throw std::runtime_error("файл пуст: " + path);
    return hex;
}

/** Hex-число фиксированной ширины: BigInt::str() отбрасывает ведущие нули. */
static std::string toHex(const BigInt& value, size_t nibbles = 0) {
    std::string hex = value.str(Base::HEX);
    if (hex.size() < nibbles) hex.insert(0, nibbles - hex.size(), '0');
    return hex;
}

/* ========================================================================= *
 *  Подкоманда: случайные байты
 * ========================================================================= */

static int cmdRandom(const Args& args) {
    const size_t count = std::stoul(args.require("bytes"));

    // random_device — системный источник энтропии (на Linux это getrandom,
    // на Windows RtlGenRandom). Детерминированные генераторы здесь нельзя:
    // предсказуемый сеансовый ключ — это полный обход шифрования.
    std::random_device entropy;
    std::vector<uint8_t> bytes(count);
    for (size_t i = 0; i < count; ++i) {
        bytes[i] = static_cast<uint8_t>(entropy() & 0xFF);
    }

    std::cout << bytesToHex(bytes) << "\n";
    return 0;
}

/* ========================================================================= *
 *  Подкоманды: «Кузнечик» в режиме CTR
 *
 *  Шифрование и расшифрование — одна и та же операция (XOR с гаммой),
 *  поэтому обе подкоманды ведут сюда.
 * ========================================================================= */

static int cmdKuznyechik(const Args& args) {
    const std::string keyHex = args.require("key");
    const std::string ivHex  = args.require("iv");

    if (keyHex.size() != KUZ_KEY_BYTES * 2) {
        throw std::invalid_argument("--key должен быть " + std::to_string(KUZ_KEY_BYTES * 2) +
                                    " hex-цифр (256 бит)");
    }
    if (ivHex.size() != KUZ_IV_BYTES * 2) {
        throw std::invalid_argument("--iv должен быть " + std::to_string(KUZ_IV_BYTES * 2) +
                                    " hex-цифр (64 бита)");
    }

    std::vector<uint8_t> data = readFile(args.require("in"));
    kuznyechikCtr(data, BigInt(keyHex.c_str()), hexToBytes(ivHex));
    writeFile(args.require("out"), data);
    return 0;
}

/* ========================================================================= *
 *  Подкоманда: Стрибог
 * ========================================================================= */

static int cmdStribog(const Args& args) {
    const int bits = std::stoi(args.optional("bits", "512"));
    std::vector<uint8_t> data = readFile(args.require("in"));
    std::cout << toHex(stribogHash(data, bits), bits / 4) << "\n";
    return 0;
}

/* ========================================================================= *
 *  Подкоманда: KDF для паролей
 *
 *  Пароль нельзя хранить ни открытым текстом, ни одиночным хешем: один
 *  Стрибог считается быстро, и словарь из миллиона паролей перебирается
 *  почти мгновенно. Поэтому хеш считается многократно:
 *
 *      h = Stribog512(salt || password)
 *      повторить iterations раз:  h = Stribog512(h || salt)
 *
 *  Соль (уникальная для каждого пользователя) обесценивает радужные
 *  таблицы: один предвычисленный словарь больше не годится сразу для всех.
 *  Число итераций задаёт стоимость одной проверки — и ровно во столько же
 *  раз дорожает перебор.
 *
 *  Честное ограничение, которое надо назвать самому: конструкция
 *  затрудняет перебор по времени (CPU), но не по памяти. Argon2id
 *  дополнительно требует от атакующего гигабайты RAM, что обесценивает
 *  перебор на GPU. Стрибог выбран потому, что это собственная
 *  реализованная примитива, а не потому, что он равен Argon2.
 *
 *  Весь цикл идёт внутри C++: iterations запусков процесса из Python
 *  заняли бы часы вместо долей секунды.
 * ========================================================================= */

static int cmdKdf(const Args& args) {
    const std::vector<uint8_t> salt = hexToBytes(args.require("salt"));
    const std::vector<uint8_t> password = readFile(args.require("password-file"));
    const size_t iterations = std::stoul(args.require("iterations"));

    std::vector<uint8_t> input = salt;
    input.insert(input.end(), password.begin(), password.end());
    std::vector<uint8_t> digest = bigIntToBytes(stribogHash(input, 512), 64);

    for (size_t i = 0; i < iterations; ++i) {
        std::vector<uint8_t> round = digest;
        round.insert(round.end(), salt.begin(), salt.end());
        digest = bigIntToBytes(stribogHash(round, 512), 64);
    }

    std::cout << bytesToHex(digest) << "\n";
    return 0;
}

/* ========================================================================= *
 *  Подкоманды: RSA
 *
 *  Внимание — это «учебная» RSA: m^e mod n без схемы заполнения (padding).
 *  Следствия, которые надо знать и назвать в отчёте:
 *    - шифрование детерминировано: одинаковые сообщения дают одинаковый
 *      шифртекст, значит, утекает информация о повторах;
 *    - шифртексты перемножаемы: c1*c2 mod n расшифруется в m1*m2, чего
 *      в настоящей схеме (OAEP) быть не должно;
 *    - подпись без PSS уязвима к некоторым экзистенциальным подделкам.
 *  См. RFC 8017.
 * ========================================================================= */

/** Сколько байт занимает модуль n (столько же занимает блок шифртекста). */
static size_t modulusBytes(const BigInt& n) {
    return (n.bitLength() + 7) / 8;
}

static int cmdRsaKeygen(const Args& args) {
    const size_t bits = std::stoul(args.require("bits"));
    const std::string prefix = args.require("out-prefix");

    RSAKeyPair key = rsaGenerateKeys(bits);

    const std::pair<const char*, const BigInt*> parts[] = {
        {".n", &key.n}, {".e", &key.e}, {".d", &key.d}};
    for (const auto& part : parts) {
        std::ofstream file(prefix + part.first);
        file << part.second->str(Base::HEX) << "\n";
        if (!file) {
            throw std::runtime_error(std::string("не удалось записать ") + prefix + part.first);
        }
    }

    std::cout << key.n.bitLength() << "\n";   // фактический размер модуля
    return 0;
}

static int cmdRsaEncrypt(const Args& args) {
    BigInt n(readHexFile(args.require("n")).c_str());
    BigInt e(readHexFile(args.require("e")).c_str());

    std::vector<uint8_t> message = readFile(args.require("in"));
    const size_t blockBytes = modulusBytes(n);
    if (message.size() + 1 > blockBytes) {
        throw std::invalid_argument("сообщение длиннее одного RSA-блока (максимум " +
                                    std::to_string(blockBytes - 1) + " байт)");
    }

    // Один ведущий байт 0x01 перед сообщением. Это НЕ схема заполнения,
    // а сохранение длины: BigInt не хранит ведущие нули, и без маркера
    // сообщение, начинающееся с нулевого байта, вернулось бы короче.
    std::vector<uint8_t> framed;
    framed.push_back(0x01);
    framed.insert(framed.end(), message.begin(), message.end());

    BigInt ciphertext = rsaEncrypt(bytesToBigInt(framed), e, n);
    writeFile(args.require("out"), bigIntToBytes(ciphertext, blockBytes));
    return 0;
}

static int cmdRsaDecrypt(const Args& args) {
    BigInt n(readHexFile(args.require("n")).c_str());
    BigInt d(readHexFile(args.require("d")).c_str());

    std::vector<uint8_t> ciphertext = readFile(args.require("in"));
    BigInt plain = rsaDecrypt(bytesToBigInt(ciphertext), d, n);

    // Снимаем маркер 0x01, добавленный при шифровании.
    std::vector<uint8_t> framed = bigIntToBytes(plain, modulusBytes(n));
    size_t start = 0;
    while (start < framed.size() && framed[start] == 0x00) ++start;
    if (start >= framed.size() || framed[start] != 0x01) {
        throw std::runtime_error("расшифрование дало неверный формат блока: "
                                 "не тот ключ или повреждённый шифртекст");
    }
    writeFile(args.require("out"),
              std::vector<uint8_t>(framed.begin() + start + 1, framed.end()));
    return 0;
}

/*
 * ЭЦП. Подписывается не документ, а его хеш:
 *
 *      подпись  = Stribog512(документ) ^ d mod n
 *      проверка: подпись ^ e mod n == Stribog512(документ)
 *
 * Хеш нужен по двум причинам: документ длиной в мегабайты просто не
 * поместится в один блок RSA, и возведение в степень по модулю 32768 бит
 * для каждого блока было бы недопустимо медленным.
 */
static int cmdRsaSign(const Args& args) {
    BigInt n(readHexFile(args.require("n")).c_str());
    BigInt d(readHexFile(args.require("d")).c_str());

    BigInt digest = stribogHash(readFile(args.require("in")), 512);
    BigInt signature = rsaDecrypt(digest, d, n);     // то же возведение в степень, но на d

    std::cout << toHex(signature, modulusBytes(n) * 2) << "\n";
    return 0;
}

static int cmdRsaVerify(const Args& args) {
    BigInt n(readHexFile(args.require("n")).c_str());
    BigInt e(readHexFile(args.require("e")).c_str());
    BigInt signature(readHexFile(args.require("sig")).c_str());

    BigInt expected = stribogHash(readFile(args.require("in")), 512);
    BigInt recovered = rsaEncrypt(signature, e, n);

    const bool valid = (recovered == expected);
    std::cout << (valid ? "OK" : "FAIL") << "\n";
    return valid ? 0 : 1;
}

/* ========================================================================= *
 *  Самопроверка: контрольные векторы ГОСТ плюс круговые прогоны
 *
 *  Запускается без аргументов и без файлов, поэтому годится и как smoke-тест
 *  после сборки, и как доказательство на защите.
 * ========================================================================= */

static bool checkEqual(const std::string& name, const std::string& got,
                       const std::string& want) {
    const bool ok = (got == want);
    std::cout << (ok ? "  OK   " : "  FAIL ") << name << "\n";
    if (!ok) {
        std::cout << "         получено:  " << got << "\n";
        std::cout << "         ожидалось: " << want << "\n";
    }
    return ok;
}

static int cmdSelftest() {
    bool ok = true;

    std::cout << "Кузнечик — ГОСТ Р 34.12-2015, приложение A\n";
    const BigInt kuzKey("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");

    // Развёртка ключа проверяется по всем десяти раундовым ключам из стандарта.
    // Это важнее проверки одного блока: именно здесь была ошибка, из-за которой
    // шифр игнорировал переданный ключ.
    const char* referenceRoundKeys[10] = {
        "8899aabbccddeeff0011223344556677", "fedcba98765432100123456789abcdef",
        "db31485315694343228d6aef8cc78c44", "3d4553d8e9cfec6815ebadc40a9ffd04",
        "57646468c44a5e28d3e59246f429f1ac", "bd079435165c6432b532e82834da581b",
        "51e640757e8745de705727265a0098b1", "5a7925017b9fdd3ed72a91a22286f984",
        "bb44e25378c73123a5f32f73cdb6e517", "72e9dd7416bcf45b755dbaa88e4a4043"};
    generateKeys(kuzKey);
    for (int i = 0; i < 10; ++i) {
        ok &= checkEqual("раундовый ключ K" + std::to_string(i + 1), toHex(keys[i], 32),
                         referenceRoundKeys[i]);
    }

    ok &= checkEqual("шифрование блока",
                     toHex(grasshopperCode(BigInt("1122334455667700ffeeddccbbaa9988"), kuzKey), 32),
                     "7f679d90bebc24305a468d42b9d4edcd");
    ok &= checkEqual("расшифрование блока",
                     toHex(grasshopperDeCode(BigInt("7f679d90bebc24305a468d42b9d4edcd"), kuzKey), 32),
                     "1122334455667700ffeeddccbbaa9988");

    std::cout << "\nCTR — круговые прогоны\n";
    {
        // 100 байт: не кратно 16, значит проверяется и обрезка последнего блока.
        std::vector<uint8_t> plain(100);
        for (size_t i = 0; i < plain.size(); ++i) plain[i] = static_cast<uint8_t>(i * 7);
        const std::vector<uint8_t> original = plain;
        const std::vector<uint8_t> iv = hexToBytes("0011223344556677");

        kuznyechikCtr(plain, kuzKey, iv);
        ok &= checkEqual("шифртекст отличается от текста",
                         plain == original ? "совпадает" : "отличается", "отличается");
        ok &= checkEqual("длина сохранена", std::to_string(plain.size()), "100");

        kuznyechikCtr(plain, kuzKey, iv);     // та же операция расшифровывает
        ok &= checkEqual("расшифрование вернуло исходные байты", bytesToHex(plain),
                         bytesToHex(original));

        // Другой IV должен давать другую гамму — иначе правило «не повторять IV»
        // не имело бы смысла.
        std::vector<uint8_t> a = original, b = original;
        kuznyechikCtr(a, kuzKey, hexToBytes("0000000000000001"));
        kuznyechikCtr(b, kuzKey, hexToBytes("0000000000000002"));
        ok &= checkEqual("разные IV дают разный шифртекст",
                         a == b ? "совпадает" : "отличается", "отличается");
    }

    std::cout << "\nСтрибог — ГОСТ Р 34.11-2012, приложение A\n";
    {
        // M1: 63 байта, один блок.
        std::vector<uint8_t> m1 = hexToBytes(
            "3231303938373635343332313039383736353433323130393837363534333231"
            "30393837363534333231303938373635343332313039383736353433323130");
        ok &= checkEqual("512 бит, M1 (63 байта)", toHex(stribogHash(m1, 512), 128),
                         "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00"
                         "fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b");
        ok &= checkEqual("256 бит, M1 (63 байта)", toHex(stribogHash(m1, 256), 64),
                         "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d");

        // M2: 72 байта — больше одного блока, проверяет весь цикл по блокам.
        std::vector<uint8_t> m2 = hexToBytes(
            "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2"
            "f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202c"
            "e8f0f2e5e220e5d1");
        ok &= checkEqual("512 бит, M2 (72 байта)", toHex(stribogHash(m2, 512), 128),
                         "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f03"
                         "7613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e");
        ok &= checkEqual("256 бит, M2 (72 байта)", toHex(stribogHash(m2, 256), 64),
                         "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d");
    }

    std::cout << "\nRSA — учебный пример p=61, q=53\n";
    {
        const BigInt n(3233), e(17), d(2753);
        ok &= checkEqual("65^17 mod 3233", rsaEncrypt(BigInt(65), e, n).str(), "2790");
        ok &= checkEqual("2790^2753 mod 3233", rsaDecrypt(BigInt(2790), d, n).str(), "65");
    }

    std::cout << "\n" << (ok ? "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ" : "ЕСТЬ ОШИБКИ") << "\n";
    return ok ? 0 : 1;
}

/* ========================================================================= *
 *  main
 * ========================================================================= */

static void printUsage() {
    std::cerr <<
        "crypto_cli — примитивы ГОСТ для веб-приложения\n"
        "\n"
        "  selftest\n"
        "        контрольные векторы ГОСТ и круговые прогоны\n"
        "  random       --bytes <N>\n"
        "        N случайных байт системного генератора, hex в stdout\n"
        "  kuz-encrypt  --key <hex64> --iv <hex16> --in <файл> --out <файл>\n"
        "  kuz-decrypt  --key <hex64> --iv <hex16> --in <файл> --out <файл>\n"
        "        Кузнечик в режиме CTR; обе команды делают одно и то же\n"
        "  stribog      --bits <256|512> --in <файл>\n"
        "        хеш файла, hex в stdout\n"
        "  kdf          --salt <hex> --password-file <файл> --iterations <N>\n"
        "        хеш пароля: Стрибог с солью и N повторами, hex в stdout\n"
        "  rsa-keygen   --bits <N> --out-prefix <префикс> [--verbose]\n"
        "        создаёт <префикс>.n, <префикс>.e, <префикс>.d; размер n в stdout\n"
        "  rsa-encrypt  --n <файл> --e <файл> --in <файл> --out <файл>\n"
        "  rsa-decrypt  --n <файл> --d <файл> --in <файл> --out <файл>\n"
        "  rsa-sign     --n <файл> --d <файл> --in <файл>\n"
        "        подпись хеша документа, hex в stdout\n"
        "  rsa-verify   --n <файл> --e <файл> --in <файл> --sig <файл>\n"
        "        OK и код 0, либо FAIL и код 1\n"
        "\n"
        "Общий флаг --verbose включает трассировку в stderr.\n"
        "stdout всегда содержит только результат; код возврата 0 — успех.\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 2;
    }

    const std::string command = argv[1];

    try {
        if (command == "selftest") return cmdSelftest();
        if (command == "--help" || command == "-h" || command == "help") {
            printUsage();
            return 0;
        }

        const Args args(argc, argv, 2);
        if (args.has("verbose")) {
            grasshopperVerbose = true;
            rsaVerbose = true;
        }

        if (command == "random")      return cmdRandom(args);
        if (command == "kuz-encrypt") return cmdKuznyechik(args);
        if (command == "kuz-decrypt") return cmdKuznyechik(args);
        if (command == "stribog")     return cmdStribog(args);
        if (command == "kdf")         return cmdKdf(args);
        if (command == "rsa-keygen")  return cmdRsaKeygen(args);
        if (command == "rsa-encrypt") return cmdRsaEncrypt(args);
        if (command == "rsa-decrypt") return cmdRsaDecrypt(args);
        if (command == "rsa-sign")    return cmdRsaSign(args);
        if (command == "rsa-verify")  return cmdRsaVerify(args);

        std::cerr << "Неизвестная команда: " << command << "\n\n";
        printUsage();
        return 2;

    } catch (const std::exception& error) {
        std::cerr << "Ошибка: " << error.what() << "\n";
        return 1;
    }
}
