#include "cryptography.h"
#include <fstream>

/**
 * Трассировка алгоритма.
 *
 * Весь пошаговый вывод (раунды, ключи, константы) идёт через dbg(), а не через
 * std::cout. Причина простая: stdout принадлежит только результату — таков
 * контракт crypto_cli (одна строка ответа и ничего больше). Трассировка по
 * умолчанию выключена; флаг --verbose включает её и направляет в stderr.
 */
bool grasshopperVerbose = false;

static std::ostream& dbg() {
    // Поток, который никогда не открывали: запись в него молча теряется.
    static std::ofstream discarded;
    return grasshopperVerbose ? std::cerr : static_cast<std::ostream&>(discarded);
}

/**
 * S- и L-преобразования идут по словам BigInt, поэтому блок обязан занимать
 * ровно два 64-битных слова. BigInt, построенный из короткого числа, может
 * иметь одно слово — тогда старшие 8 байт просто не попадут под замену.
 */
static void fitTo128Bits(BigInt& block) {
    if (block.numbers.size() < 2) block.numbers.resize(2, 0);
}

/**
 * S-блок (таблица замен) для алгоритма Grasshopper 
 * Используется для нелинейного преобразования байтов в S-преобразовании
 */
uint8_t P[] = {
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 
    119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 
    90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 
    160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 
    104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156,  
    183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 
    177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 
    245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 
    222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 
    98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 
    165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 
    217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 
    97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 
    116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
};

/**
 * Коэффициенты для линейного преобразования в R-функции
 * Используются для умножения в поле GF(2^8) с образующим полиномом x^8 + x^7 + x^6 + x + 1
 */
uint8_t L_COEFF[16] = {
    1,   148, 32, 133,
    16,  194, 192, 1,
    251, 1,   192, 194,
    16,  133, 32, 148
};

/**
 * Умножение в поле GF(2^8) с образующим полиномом x^8 + x^7 + x^6 + x + 1 = 0xC3
 * @param a - первый множитель
 * @param b - второй множитель
 * @return результат умножения a * b в поле GF(2^8)
 */
uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        // Если младший бит b установлен, добавляем a к результату
        if (b & 1) result ^= a;
        // Проверяем старший бит a для переноса
        bool hi_bit_set = a & 0x80;
        a <<= 1;  // Сдвигаем a влево
        // Если был перенос, применяем модульную редукцию
        if (hi_bit_set) a ^= 0xC3;  // 0xC3 соответствует полиному x^8 + x^7 + x^6 + x + 1
        b >>= 1;  // Сдвигаем b вправо
    }
    return result;
}

/**
 * Линейное преобразование для R-функции
 * Вычисляет линейную комбинацию байтов с коэффициентами L_COEFF
 * @param byteArray - массив из 16 байтов для преобразования
 * @return результат линейного преобразования
 */
uint8_t linearfunc(uint8_t* byteArray) {
    uint8_t res = 0;
    // Умножаем каждый байт на соответствующий коэффициент и складываем (XOR)
    for(int i = 0; i < 16; i++) {
        res ^= gf_mul(byteArray[i], L_COEFF[15 - i]);
    }
    return res;
}

/**
 * R-преобразование (линейное преобразование) для алгоритма Grasshopper
 * Выполняет циклический сдвиг и линейное преобразование
 * @param high - старшие 64 бита блока (изменяется на месте)
 * @param low - младшие 64 бита блока (изменяется на месте)
 */
void Rfunc(uint64& high, uint64& low) {
    uint8_t bytes[16];  // Буфер для 16 байтов (128 бит)
    
    // Разбиваем 128-битный блок на байты (big-endian порядок)
    for(int i = 0; i < 8; i++) {
        bytes[i]     = (high >> (8*(7-i))) & 0xFF;  // Старшие 8 байтов
        bytes[i+8]   = (low  >> (8*(7-i))) & 0xFF;  // Младшие 8 байтов
    }

    // Вычисляем новый первый байт с помощью линейного преобразования
    uint8_t a0_new = linearfunc(bytes);

    // Циклический сдвиг байтов вправо
    for(int i = 15; i > 0; i--) {
        bytes[i] = bytes[i-1];
    }
    bytes[0] = a0_new;  // Новый первый байт

    // Собираем байты обратно в 128-битный блок
    high = 0;
    low  = 0;
    for(int i = 0; i < 8; i++) {
        high = (high << 8) | bytes[i];    // Старшие 64 бита
        low  = (low << 8)  | bytes[i+8];  // Младшие 64 бита
    }
}

/**
 * Обратное R-преобразование для расшифрования
 * @param high - старшие 64 бита блока (изменяется на месте)
 * @param low - младшие 64 бита блока (изменяется на месте)
 */
void ReverseRfunc(uint64& high, uint64& low) {
    uint8_t bytes[16];
    
    // Разбиваем блок на байты
    for(int i = 0; i < 8; i++) {
        bytes[i]     = (high >> (8*(7-i))) & 0xFF;
        bytes[i+8]   = (low  >> (8*(7-i))) & 0xFF;
    }

    // Сохраняем первый байт и сдвигаем влево
    uint8_t first = bytes[0];
    for(int i = 0; i < 15; i++) {
        bytes[i] = bytes[i+1];
    }
    // Восстанавливаем последний байт с линейным преобразованием
    bytes[15] = first;
    bytes[15] = linearfunc(bytes);

    // Собираем обратно
    high = 0;
    low  = 0;
    for(int i = 0; i < 8; i++) {
        high = (high << 8) | bytes[i];
        low  = (low  << 8) | bytes[i+8];
    }
}

/**
 * L-преобразование - 16-кратное применение R-преобразования
 * @param high - старшие 64 бита блока (изменяется на месте)
 * @param low - младшие 64 бита блока (изменяется на месте)
 */
void Lfunc(uint64& high, uint64& low) {
    for(int i = 0; i < 16; i++) {
        Rfunc(high, low);
    }
}

/**
 * Обратное L-преобразование для расшифрования
 * @param high - старшие 64 бита блока (изменяется на месте)
 * @param low - младшие 64 бита блока (изменяется на месте)
 */
void ReverseLfunc(uint64& high, uint64& low) {
    for(int i = 0; i < 16; i++) {
        ReverseRfunc(high, low);
    }
}

// Вспомогательные функции для работы с BigInt

/**
 * Применение L-преобразования к BigInt
 * @param num - число для преобразования (изменяется на месте)
 */
void LfuncBigInt(BigInt& num) {
    // Убеждаемся, что число имеет достаточно слов для 128 бит
    if (num.numbers.size() < 2) {
        num.numbers.resize(2, 0);
    }
    // Применяем L-преобразование к двум 64-битным словам
    Lfunc(num.numbers[1], num.numbers[0]);
}

/**
 * Применение обратного L-преобразования к BigInt
 * @param num - число для преобразования (изменяется на месте)
 */
void ReverseLfuncBigInt(BigInt& num) {
    if (num.numbers.size() < 2) {
        num.numbers.resize(2, 0);
    }
    ReverseLfunc(num.numbers[1], num.numbers[0]);
}

/**
 * S-преобразование для Grasshopper - нелинейная замена байтов
 * @param number - число для преобразования (изменяется на месте)
 */
void SfuncGrassHopper(BigInt& number) {
    for (size_t i = 0; i < number.numbers.size(); ++i) {
        uint64 word = number.numbers[i];
        uint64 newWord = 0;
        // Обрабатываем каждый байт в 64-битном слове
        for (int b = 0; b < 8; ++b) {
            uint8_t byte = (word >> (8 * b)) & 0xFF;  // Извлекаем байт
            uint8_t sub = P[byte];                    // Заменяем через S-блок
            newWord |= (uint64)sub << (8 * b);        // Собираем новое слово
        }
        number.numbers[i] = newWord;
    }
}

/**
 * Обратный S-блок для расшифрования
 */
uint8_t P_INV[256];
bool inverseSBoxBuilt = false;

/**
 * Построение обратного S-блока P_INV из прямого S-блока P
 */
void buildInverseSBox() {
    if (inverseSBoxBuilt) return;
    // Для каждого значения в P устанавливаем обратное отображение
    for (int i = 0; i < 256; i++) {
        P_INV[P[i]] = i;  // P_INV[P[x]] = x
    }
    inverseSBoxBuilt = true;
}

/**
 * Обратное S-преобразование для расшифрования
 * @param number - число для преобразования (изменяется на месте)
 */
void ReverseSfuncGrassHopper(BigInt& number) {
    // Строим обратный S-блок при первом вызове
    if (!inverseSBoxBuilt) {
        buildInverseSBox();
    }
    for (size_t i = 0; i < number.numbers.size(); ++i) {
        uint64 word = number.numbers[i];
        uint64 newWord = 0;
        for (int b = 0; b < 8; ++b) {
            uint8_t byte = (word >> (8 * b)) & 0xFF;
            uint8_t sub = P_INV[byte];  // Используем обратный S-блок
            newWord |= (uint64)sub << (8 * b);
        }
        number.numbers[i] = newWord;
    }
}

/**
 * Массив из 10 раундовых ключей K1..K10.
 */
BigInt keys[10];

/**
 * Одно применение функции F из ГОСТ Р 34.12-2015 (п. 4.4).
 *
 *     F[C](a1, a0) = ( L(S(a1 XOR C)) XOR a0 ,  a1 )
 *
 * То есть старшая половина пары прогоняется через XOR-S-L, складывается
 * (XOR) с младшей и становится новой старшей; прежняя старшая съезжает
 * в младшую. Раундовая константа C_i = L(i) — число i, положенное
 * в младший байт 128-битного блока и прогнанное через L.
 *
 * @param a1 старшая половина пары, изменяется на месте
 * @param a0 младшая половина пары, изменяется на месте
 * @param i  номер константы, 1..32
 */
void Ffunc(BigInt& a1, BigInt& a0, int i) {
    uint64 highC = 0;
    uint64 lowC  = static_cast<uint64>(i);
    Lfunc(highC, lowC);

    BigInt constant;
    constant.numbers.resize(2);
    constant.numbers[0] = lowC;
    constant.numbers[1] = highC;

    dbg() << "  C" << i << " = " << constant.str(Base::HEX) << "\n";

    BigInt mixed = a1 ^ constant;   // X[C]
    fitTo128Bits(mixed);
    SfuncGrassHopper(mixed);        // S
    LfuncBigInt(mixed);             // L
    mixed = mixed ^ a0;              // XOR с младшей половиной
    fitTo128Bits(mixed);

    a0 = a1;                       // пара сдвигается
    a1 = mixed;
}

/**
 * Развёртка ключа: из 256-битного мастер-ключа получаем 10 раундовых ключей.
 *
 * ГОСТ Р 34.12-2015, п. 4.4:
 *   (K1, K2) = (старшие 128 бит ключа, младшие 128 бит ключа)
 *   (K[2i+1], K[2i+2]) = F[C_8i] o ... o F[C_{8(i-1)+1}] (K[2i-1], K[2i]),  i = 1..4
 *
 * То есть каждая следующая пара ключей — это восемь применений F к предыдущей
 * паре, со своей восьмёркой констант. Всего 32 константы и 4 пары.
 *
 * @param key 256-битный мастер-ключ
 */
void generateKeys(const BigInt& key) {
    // Мастер-ключ — ровно 4 слова по 64 бита. Короткий ключ (с ведущими
    // нулями) дополняем, иначе половинки разъедутся.
    BigInt master = key;
    if (master.numbers.size() < 4) master.numbers.resize(4, 0);

    BigInt a1, a0;                                       // текущая пара
    a1.numbers = { master.numbers[2], master.numbers[3] };  // старшие 128 бит
    a0.numbers = { master.numbers[0], master.numbers[1] };  // младшие 128 бит

    keys[0] = a1;   // K1
    keys[1] = a0;   // K2

    for (int pairIndex = 1; pairIndex <= 4; ++pairIndex) {
        dbg() << "Развёртка пары " << pairIndex << ":\n";
        for (int step = 1; step <= 8; ++step) {
            Ffunc(a1, a0, (pairIndex - 1) * 8 + step);
        }
        keys[2 * pairIndex]     = a1;   // K3, K5, K7, K9
        keys[2 * pairIndex + 1] = a0;   // K4, K6, K8, K10
    }

    for (int i = 0; i < 10; ++i) {
        dbg() << "K" << (i + 1) << " = " << keys[i].str(Base::HEX) << "\n";
    }
}

/**
 * Функция шифрования Grasshopper 
 * @param message - открытый текст для шифрования (128 бит)
 * @param key - ключ шифрования (256 бит)
 * @return шифртекст
 */
BigInt grasshopperCode(const BigInt& message, const BigInt& key) {
    dbg() << "Начало шифрования...\n";
    
    // Генерация раундовых ключей
    generateKeys(key);
    
    BigInt res = message;
    fitTo128Bits(res);
    dbg() << "Исходное сообщение: " << res.str(Base::HEX) << "\n\n";
    
    // 9 раундов преобразования: XOR → S → L
    for(int i = 0; i < 9; i++) {
        dbg() << "Раунд " << i << ":\n";
        dbg() << "  До XOR с ключом: " << res.str(Base::HEX) << "\n";
        dbg() << "  Ключ K" << (i+1) << ": " << keys[i].str(Base::HEX) << "\n";
        res = res ^ keys[i];
        dbg() << "  После XOR: " << res.str(Base::HEX) << "\n";
        SfuncGrassHopper(res);
        dbg() << "  После S: " << res.str(Base::HEX) << "\n";
        LfuncBigInt(res);
        dbg() << "  После L: " << res.str(Base::HEX) << "\n\n";
    }
    
    // Финальный раунд: только XOR с K10
    dbg() << "Финальный раунд:\n";
    dbg() << "  До XOR с ключом K10: " << res.str(Base::HEX) << "\n";
    dbg() << "  Ключ K10: " << keys[9].str(Base::HEX) << "\n";
    res = res ^ keys[9];
    dbg() << "  Результат: " << res.str(Base::HEX) << "\n\n";
    
    return res;
}

/**
 * Функция расшифрования Grasshopper 
 * @param message - шифртекст для расшифрования (128 бит)
 * @param key - ключ шифрования (256 бит)
 * @return открытый текст
 */
BigInt grasshopperDeCode(const BigInt& message, const BigInt& key) {
    dbg() << "Начало расшифрования...\n";
    
    // Генерация тех же раундовых ключей
    generateKeys(key);
    buildInverseSBox();  // Строим обратный S-блок
    
    BigInt res = message;
    fitTo128Bits(res);
    dbg() << "Зашифрованное сообщение: " << res.str(Base::HEX) << "\n\n";
    
    // Финальный XOR с K10 (обратная операция)
    dbg() << "Финальный XOR с K10:\n";
    dbg() << "  До XOR: " << res.str(Base::HEX) << "\n";
    dbg() << "  Ключ K10: " << keys[9].str(Base::HEX) << "\n";
    res = res ^ keys[9];
    dbg() << "  После XOR: " << res.str(Base::HEX) << "\n\n";
    
    // 9 раундов в обратном порядке: L⁻¹ → S⁻¹ → XOR
    for(int i = 8; i >= 0; i--) {
        dbg() << "Раунд " << (9-i) << " (обратный):\n";
        dbg() << "  До обратного L: " << res.str(Base::HEX) << "\n";
        ReverseLfuncBigInt(res);
        dbg() << "  После обратного L: " << res.str(Base::HEX) << "\n";
        dbg() << "  До обратного S: " << res.str(Base::HEX) << "\n";
        ReverseSfuncGrassHopper(res);
        dbg() << "  После обратного S: " << res.str(Base::HEX) << "\n";
        dbg() << "  Ключ K" << (i+1) << ": " << keys[i].str(Base::HEX) << "\n";
        res = res ^ keys[i];
        dbg() << "  После XOR: " << res.str(Base::HEX) << "\n\n";
    }
    
    dbg() << "Расшифрованный текст: " << res.str(Base::HEX) << "\n\n";
    return res;
}