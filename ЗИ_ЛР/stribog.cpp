#include "cryptography.h"
#include <cstring>
#include <stdexcept>
#include <vector>

/**
 * S-блок (таблица замен) для алгоритма Стрибог 
 * Каждый байт входных данных заменяется на соответствующий байт из этой таблицы
 */
uint8_t S[256] = {
    252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250,
    218,  35, 197,   4,  77, 233, 119, 240, 219, 147,  46,
    153, 186,  23,  54, 241, 187,  20, 205,  95, 193, 249,
     24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66,
    139,   1, 142,  79,   5, 132,   2, 174, 227, 106, 143,
    160,  6,  11, 237, 152, 127, 212, 211,  31, 235,  52,
     44,  81, 234, 200,  72, 171, 242,  42, 104, 162, 253,
     58, 206, 204, 181, 112,  14,  86,   8,  12, 118,  18, 
    191, 114,  19,  71, 156, 183,  93, 135,  21, 161, 150,
     41,  16, 123, 154, 199, 243, 145,  120, 111, 157, 158,
    178, 177,  50, 117,  25,  61, 255,  53, 138, 126, 109,
     84, 198, 128, 195, 189,  13,  87, 223, 245,  36, 169,
     62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,
      3, 224,  15, 236, 222, 122, 148, 176, 188, 220, 232,
     40,  80,  78,  51,  10,  74, 167, 151,  96, 115,  30,
      0,  98,  68,  26, 184,  56, 130, 100, 159,  38,  65,
    173,  69,  70, 146,  39,  94,  85,  47, 140, 163, 165,
    125, 105, 213, 149,  59,   7,  88, 179,  64, 134, 172,
     29, 247,  48,  55, 107, 228, 136, 217, 231, 137, 225,
     27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144,
    202, 216, 133,  97,  32, 113, 103, 164,  45,  43,   9,
     91, 203, 155,  37, 208, 190, 229, 108,  82,  89, 166,
    116, 210, 230, 244, 180, 192, 209, 102, 175, 194,  57,
     75,  99, 182
};

/**
 * Таблица перестановки Tau для P-преобразования
 * Определяет новый порядок байтов после перестановки
 */
const int Tau[64] = {
    0, 8,16,24,32,40,48,56,
    1, 9,17,25,33,41,49,57,
    2,10,18,26,34,42,50,58,
    3,11,19,27,35,43,51,59,
    4,12,20,28,36,44,52,60,
    5,13,21,29,37,45,53,61,
    6,14,22,30,38,46,54,62,
    7,15,23,31,39,47,55,63
};

/**
 * Константы C_i для алгоритма Стрибог
 * Используются в итерациях сжатия хеш-функции
 */
std::vector<BigInt> C = {
    BigInt("b1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507"),
    BigInt("6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7"),
    BigInt("f574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2"),
    BigInt("ef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e"),
    BigInt("4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbdbfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57"),
    BigInt("ae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e"),
    BigInt("f4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493"),
    BigInt("9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e"),
    BigInt("378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb"),
    BigInt("abbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced"), 
    BigInt("7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b"), 
    BigInt("378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720")  
};

/**
 * Матрица линейного преобразования L для алгоритма Стрибог
 * Используется в L-преобразовании для диффузии битов
 */
uint64_t L[64] = {
    0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
    0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
    0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
    0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
    0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
    0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
    0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
    0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
    0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
    0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
    0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
    0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
    0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
    0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
    0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
    0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083,
};

/**
 * S-преобразование (нелинейное преобразование)
 * Заменяет каждый байт числа на соответствующий байт из S-блока
 * @param number - входное число для преобразования (изменяется на месте)
 */
void Sfunc(BigInt& number) {
    for (size_t i = 0; i < number.numbers.size(); ++i) {
        uint64_t word = number.numbers[i];
        uint64_t newWord = 0;
        // Обрабатываем каждый байт в 64-битном слове
        for (int b = 0; b < 8; ++b) {
            uint8_t byte = (word >> (8 * b)) & 0xFF;  // Извлекаем байт
            uint8_t sub = S[byte];                    // Заменяем через S-блок
            newWord |= (uint64_t)sub << (8 * b);      // Собираем новое слово
        }
        number.numbers[i] = newWord;
    }
}

/**
 * P-преобразование (перестановка байтов)
 * Переставляет байты согласно таблице Tau
 * @param number - входное число для преобразования (изменяется на месте)
 */
void Pfunc(BigInt& number) {
    uint8_t block[64];  // Буфер для 64 байт (512 бит)
    
    // Разбиваем BigInt на массив байтов
    for (size_t i = 0; i < 8; ++i) {
        uint64_t word = number.numbers[i];
        for (int b = 0; b < 8; ++b) {
            block[i*8 + b] = (word >> (8*b)) & 0xFF;
        }
    }
    
    // Применяем перестановку Tau
    uint8_t tmp[64];
    for (int i = 0; i < 64; ++i) 
        tmp[i] = block[Tau[i]];
    
    // Собираем обратно в BigInt
    for (size_t i = 0; i < 8; ++i) {
        uint64_t newWord = 0;
        for (int b = 0; b < 8; ++b)
            newWord |= ((uint64_t)tmp[i*8 + b] << (8*b));
        number.numbers[i] = newWord;
    }
}

/**
 * L-преобразование (линейное преобразование)
 * Умножает данные на матрицу L в поле GF(2)
 * @param number - входное число для преобразования (изменяется на месте)
 */
void Lfunc(BigInt& number) {
    uint8_t block[64];
    
    // Разбиваем BigInt на массив байтов (big-endian порядок)
    for (size_t i = 0; i < 8; ++i) {
        uint64_t word = number.numbers[i];
        for (int b = 0; b < 8; ++b) 
            block[i*8 + b] = (word >> (56 - 8*b)) & 0xFF;
    }
    
    uint64_t newNumbers[8] = {0};
    
    // Применяем линейное преобразование для каждого 64-битного блока
    for (int i = 0; i < 8; ++i) {
        uint64_t t = 0;
        for (int k = 0; k < 8; ++k) {
            uint8_t byte = block[i*8 + k];
            // Для каждого бита в байте
            for (int j = 0; j < 8; ++j) {
                if (byte & (1 << (7 - j))) {
                    t ^= L[8*k + j];  // XOR с соответствующим элементом матрицы L
                }
            }
        }
        newNumbers[i] = t;
    }
    
    // Записываем результат обратно
    for (size_t i = 0; i < 8; ++i) 
        number.numbers[i] = newNumbers[i];
}

/**
 * LPS-преобразование (композиция S, P, L преобразований)
 * Основное преобразование в алгоритме Стрибог
 * @param k - входной блок данных
 * @return результат применения S → P → L преобразований
 */
BigInt LPS(const BigInt& k) {
    BigInt res = k;
    Sfunc(res);  // Нелинейная замена
    Pfunc(res);  // Перестановка байтов
    Lfunc(res);  // Линейное преобразование
    return res;
}

/**
 * Функция сжатия g для алгоритма Стрибог
 * @param h - текущее значение хеша
 * @param m - блок сообщения
 * @param N - счетчик обработанных битов
 * @return новое значение хеша
 */
BigInt g(const BigInt& h, const BigInt& m, const BigInt& N) {
    // Вычисляем K = LPS(h XOR N)
    BigInt K = LPS(h ^ N);
    BigInt temp = m;
    
    // 12 раундов преобразования
    for (int i = 0; i < 12; i++) {
        temp = LPS(K ^ temp);  // Преобразование данных
        K = LPS(K ^ C[i]);     // Обновление ключа раунда
    }
    
    temp ^= K;  // Финальный XOR
    
    // Вычисляем новое значение хеша: h_new = h XOR temp XOR m
    BigInt h_new = h ^ temp ^ m;
    return h_new;
}

/* ------------------------------------------------------------------------- *
 *  Драйвер хеширования: ГОСТ Р 34.11-2012, разделы 8.1-8.3
 *
 *  Выше — проверенное ядро: S, P, L и функция сжатия g. Ниже — обвязка,
 *  которая режет сообщение произвольной длины на 512-битные блоки и
 *  накапливает три величины: h (хеш), N (счётчик бит), Sigma (сумма блоков).
 *
 *  Соглашение о порядке байт. Первый байт сообщения попадает в САМЫЙ СТАРШИЙ
 *  байт BigInt-а — ровно так, как читается hex-строка в тестовом векторе.
 *  Поэтому блок всегда строится через BigInt(hex) и всегда занимает ровно
 *  8 слов по 64 бита: S/P/L обращаются к numbers[0..7] без проверок, и блок
 *  меньшего размера означал бы чтение за границей вектора.
 * ------------------------------------------------------------------------- */

static const size_t STRIBOG_BLOCK_BYTES = 64;   // 512 бит
static const size_t STRIBOG_WORDS = 8;

/** Ровно 8 слов: короче — выход за границы в Sfunc/Pfunc/Lfunc, длиннее — мусор. */
static void fitTo512Bits(BigInt& value) {
    value.numbers.resize(STRIBOG_WORDS, 0);
}

/** 64 байта (первый байт — старший) -> BigInt из 8 слов. */
static BigInt blockToBigInt(const uint8_t* block) {
    static const char* digits = "0123456789abcdef";
    std::string hex;
    hex.reserve(STRIBOG_BLOCK_BYTES * 2);
    for (size_t i = 0; i < STRIBOG_BLOCK_BYTES; ++i) {
        hex += digits[block[i] >> 4];
        hex += digits[block[i] & 0x0F];
    }
    return BigInt(hex.c_str());
}

/** Сложение по модулю 2^512: BigInt растёт на переносе, лишнее слово надо снять. */
static void addMod512(BigInt& accumulator, const BigInt& value) {
    accumulator += value;
    fitTo512Bits(accumulator);
}

/**
 * Хеш Стрибог от произвольной последовательности байт.
 *
 * @param message        входные байты (может быть пустым)
 * @param hash_size_bits 256 или 512
 */
BigInt stribogHash(const std::vector<uint8_t>& message, int hash_size_bits) {
    if (hash_size_bits != 256 && hash_size_bits != 512) {
        throw std::invalid_argument("размер хеша должен быть 256 или 512 бит");
    }

    // Шаг 1. Инициализация. IV = нули для 512 бит и байты 0x01 для 256.
    BigInt h;
    h.numbers.assign(STRIBOG_WORDS, hash_size_bits == 256 ? 0x0101010101010101ULL : 0ULL);
    BigInt N, Sigma;
    fitTo512Bits(N);
    fitTo512Bits(Sigma);

    // Шаг 2. Полные блоки. Стандарт откусывает очередной блок с КОНЦА
    // сообщения, поэтому идём от последних 64 байт к первым.
    size_t remaining = message.size();
    while (remaining >= STRIBOG_BLOCK_BYTES) {
        const uint8_t* block = message.data() + (remaining - STRIBOG_BLOCK_BYTES);
        BigInt m = blockToBigInt(block);

        h = g(h, m, N);
        fitTo512Bits(h);
        addMod512(N, BigInt(static_cast<uint64>(STRIBOG_BLOCK_BYTES * 8)));
        addMod512(Sigma, m);

        remaining -= STRIBOG_BLOCK_BYTES;
    }

    // Шаг 3. Остаток (0..63 байта) дополняется до блока:  m = 0...0 1 || M.
    // В байтовой записи: остаток кладём в конец блока, а в байт перед ним
    // пишем 0x01 — это и есть тот самый единичный бит.
    uint8_t tail[STRIBOG_BLOCK_BYTES] = {0};
    std::memcpy(tail + STRIBOG_BLOCK_BYTES - remaining, message.data(), remaining);
    tail[STRIBOG_BLOCK_BYTES - remaining - 1] = 0x01;

    BigInt m = blockToBigInt(tail);
    h = g(h, m, N);
    fitTo512Bits(h);
    addMod512(N, BigInt(static_cast<uint64>(remaining * 8)));
    addMod512(Sigma, m);

    // Финал: домешиваем счётчик длины и контрольную сумму блоков.
    h = g(h, N, BigInt(0));
    fitTo512Bits(h);
    h = g(h, Sigma, BigInt(0));
    fitTo512Bits(h);

    // Для 256 бит берём СТАРШУЮ половину результата.
    if (hash_size_bits == 256) {
        h.shiftBitsRight(256);
    }
    return h;
}

/**
 * Совместимая обёртка для лабораторных тестов: хеширует число как есть,
 * в минимальном big-endian представлении.
 *
 * Внимание: BigInt не хранит ведущие нули, поэтому сообщение, начинающееся
 * с нулевого байта, через эту обёртку даст другой хеш. Рабочий код
 * (crypto_cli, пароли, подписи) всегда вызывает stribogHash по байтам.
 */
BigInt stribog(const BigInt& message, int hash_size_bits) {
    std::string hex = message.str(Base::HEX);
    if (hex.size() % 2 != 0) hex.insert(0, 1, '0');

    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(std::stoi(hex.substr(2 * i, 2), nullptr, 16));
    }
    if (message.isZero()) bytes.clear();
    return stribogHash(bytes, hash_size_bits);
}
