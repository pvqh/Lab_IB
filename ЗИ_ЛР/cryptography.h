#pragma once
#include <vector>
#include "BigInt.h"

struct RSAKeyPair {
    BigInt n;
    BigInt e;
    BigInt d;
};

extern bool rsaVerbose;  // print key generation progress to stderr

RSAKeyPair rsaGenerateKeys(size_t bits, const BigInt& e_in = BigInt(65537));
BigInt rsaEncrypt(const BigInt& message, const BigInt& e, const BigInt& n);
BigInt rsaDecrypt(const BigInt& message, const BigInt& d, const BigInt& n);

/* Стрибог по байтам — основной вход (произвольная длина сообщения). */
BigInt stribogHash(const std::vector<uint8_t>& message, int hash_size_bits);

/* Обёртка для лабораторных тестов: хеширует BigInt как big-endian число. */
BigInt stribog(const BigInt& message, int hash_size_bits);

extern bool grasshopperVerbose;  // print round-by-round tracing to stderr

void generateKeys(const BigInt& key);   // round-key schedule, GOST R 34.12-2015 4.4
extern BigInt keys[10];                 // K1..K10, filled by generateKeys

BigInt grasshopperCode(const BigInt& message, const BigInt& key);
BigInt grasshopperDeCode(const BigInt& message, const BigInt& key);