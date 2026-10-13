#include "kuz_ctr.h"
#include "cryptography.h"
#include <algorithm>
#include <stdexcept>

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    static const char* digits = "0123456789abcdef";
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        hex += digits[b >> 4];
        hex += digits[b & 0x0F];
    }
    return hex;
}

static int hexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::invalid_argument(std::string("не hex-цифра: '") + c + "'");
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("нечётное число hex-цифр");
    }
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(hexDigit(hex[2 * i]) << 4 | hexDigit(hex[2 * i + 1]));
    }
    return bytes;
}

BigInt bytesToBigInt(const std::vector<uint8_t>& bytes) {
    // Конструктор BigInt из hex-строки трактует её как big-endian число
    // и сам выделяет нужное число слов по длине строки.
    std::string hex = bytesToHex(bytes);
    return BigInt(hex.c_str());
}

std::vector<uint8_t> bigIntToBytes(const BigInt& value, size_t width) {
    std::string hex = value.str(Base::HEX);
    if (hex.size() > width * 2) {
        throw std::invalid_argument("число не влезает в " + std::to_string(width) + " байт");
    }
    hex.insert(0, width * 2 - hex.size(), '0');   // дополняем ведущими нулями
    return hexToBytes(hex);
}

void kuznyechikCtr(std::vector<uint8_t>& data, const BigInt& key,
                   const std::vector<uint8_t>& iv) {
    if (iv.size() != KUZ_IV_BYTES) {
        throw std::invalid_argument("IV должен быть ровно 8 байт");
    }

    for (size_t offset = 0; offset < data.size(); offset += KUZ_BLOCK_BYTES) {
        const uint64_t blockIndex = offset / KUZ_BLOCK_BYTES;

        // Блок счётчика: IV (8 байт) || номер блока (8 байт, big-endian).
        std::vector<uint8_t> counter = iv;
        for (int shift = 56; shift >= 0; shift -= 8) {
            counter.push_back(static_cast<uint8_t>(blockIndex >> shift));
        }

        // Гамма — это шифрование блока счётчика. Сами данные через шифр
        // не проходят: они только XOR-ятся с гаммой.
        BigInt gammaValue = grasshopperCode(bytesToBigInt(counter), key);
        std::vector<uint8_t> gamma = bigIntToBytes(gammaValue, KUZ_BLOCK_BYTES);

        // Последний блок может быть короче 16 байт — лишняя гамма отбрасывается.
        const size_t chunk = std::min(KUZ_BLOCK_BYTES, data.size() - offset);
        for (size_t i = 0; i < chunk; ++i) {
            data[offset + i] ^= gamma[i];
        }
    }
}
