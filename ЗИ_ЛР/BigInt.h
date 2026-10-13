#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <ostream>
#include <complex>
#include <valarray>
#include <iostream>
#include <cmath>
#include <cstring>
#include "modMath.h"
using namespace std;

typedef unsigned long long uint64;

const double PI = acos(-1);
enum class Base { DEC = 10, BIN = 2, HEX = 16 };

class BigInt {
public:
    BigInt(): isMinus(false) {}
    BigInt(const BigInt& bigInt): numbers(bigInt.numbers), isMinus(bigInt.isMinus) {}
    BigInt(BigInt&& bigInt): numbers(std::move(bigInt.numbers)), isMinus(bigInt.isMinus) {}
    BigInt(uint64 value): isMinus(false) { if(value != 0) { numbers.push_back(value); } }
    BigInt(const char* hex) {
        size_t hex_len = strlen(hex);
        size_t num_bytes = (hex_len + 1) / 2;
        size_t num_words = (num_bytes + 7) / 8;
        numbers.resize(num_words, 0);
        std::vector<uint8_t> bytes(num_words * 8, 0);

        size_t byteIndex = 0;
        for (int i = static_cast<int>(hex_len) - 1; i >= 0; i -= 2) {
            uint8_t low = 0, high = 0;
            if (isxdigit(hex[i])) {
                char c = hex[i];
                low = (c >= '0' && c <= '9') ? c - '0' :
                    (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                    (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
            }
            if (i - 1 >= 0 && isxdigit(hex[i - 1])) {
                char c = hex[i - 1];
                high = (c >= '0' && c <= '9') ? c - '0' :
                    (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                    (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
            }
            bytes[byteIndex++] = (high << 4) | low;
        }
        for (size_t i = 0; i < num_words; ++i) {
            uint64_t w = 0;
            for (size_t b = 0; b < 8; ++b) {
                w |= static_cast<uint64_t>(bytes[i * 8 + b]) << (8 * b);
            }
            numbers[i] = w;
        }
    }
    BigInt(int value): isMinus(value < 0) { if(value != 0) { numbers.push_back(abs(value)); } }
    BigInt(long long value): isMinus(value < 0) { if(value != 0) { numbers.push_back(abs(value)); } }
    BigInt(std::initializer_list<uint64> init): isMinus(false) { for (auto v : init) {  numbers.push_back(v); } }
    ~BigInt() = default;
public:
    inline unsigned long long toUint64() const { return numbers.empty() ? 0 : numbers[0]; }
    inline size_t bitLength() const {
        size_t n = numbers.size();
        while (n > 0 && numbers[n - 1] == 0) --n;   // ведущие нулевые слова не считаются
        return n == 0 ? 0 : (n - 1) * 64 + (64 - __builtin_clzll(numbers[n - 1]));
    }

    std::string str(Base base = Base::DEC) const;
    bool getBit(size_t bitIndex) const;
    bool isZero() const;
    bool isEven() const;
    bool isDivisibleBy(const BigInt& divisor) const;
    const BigInt& getBase64() const;
    void swap(BigInt& other);
    void shiftBitsRight(int shifts, BigInt* removedBits = nullptr);
    void shiftBitsLeft(int shifts, BigInt* removedBits = nullptr);
    void shiftBits(int shifts, BigInt* removedBits = nullptr);
    void setValue(uint64 value);
    void reserve(size_t size_in_bytes);
    BigInt sqrt() const;
    BigInt& pow(const BigInt& exponent);
    BigInt gcd(const BigInt& other) const;
    BigInt lcm(const BigInt& other) const;
public:
    BigInt& operator+=(const BigInt& other);
    BigInt& operator-=(const BigInt& other);
    BigInt& operator*=(const BigInt& other);
    BigInt& operator/=(const BigInt& other);
    BigInt& operator|=(const BigInt& other);
    BigInt& operator&=(const BigInt& other);
    BigInt& operator^=(const BigInt& other);
    BigInt& operator=(const BigInt& other); 
    BigInt& operator=(BigInt&& other);
    BigInt& operator++();

    BigInt operator&(const BigInt& other) const;
    BigInt operator|(const BigInt& other) const;
    BigInt operator<<(const BigInt& shifts) const;
    BigInt operator>>(const BigInt& shifts) const;
    BigInt operator+(const BigInt& other) const;
    BigInt operator-(const BigInt& other) const;
    BigInt operator^(const BigInt& other) const;
    BigInt operator*(const BigInt& other) const;
    BigInt operator/(const BigInt& other) const;
    BigInt operator%(const BigInt& other) const;
    
    // Операторы сравнения
    bool operator<(const BigInt& other) const;
    bool operator<=(const BigInt& other) const;
    bool operator>(const BigInt& other) const;
    bool operator>=(const BigInt& other) const;
    bool operator==(const BigInt& other) const;
    bool operator!=(const BigInt& other) const;

    friend BigInt operator*(int lhs, const BigInt& rhs) { return BigInt(lhs) * rhs; }
    friend BigInt operator-(int lhs, const BigInt& rhs) { return BigInt(lhs) - rhs; }
public:
    void addVectors(const BigInt& other);
    void subtractVectors(const BigInt& other);
    void multiplyInto(const BigInt& other, BigInt& result) const;
    std::pair<BigInt, BigInt> divmod(const BigInt& a, const BigInt& b) const;
    std::pair<BigInt, BigInt> divmod1(const BigInt& a, const BigInt& b) const;
    void divmodInto(const BigInt& a, const BigInt& b, BigInt& quotient, BigInt& remainder) const;
    std::string toPowerOfTwoBase(size_t k) const;
public:
    std::vector<uint64> numbers;
    bool isMinus = false;
};

inline std::ostream& operator<<(std::ostream& os, const BigInt& value) {
    os << value.str();
    return os;
}

bool getBit(const BigInt& value, size_t bitIndex);
BigInt pow(const BigInt& number, const BigInt& exponent);
BigInt random(const BigInt& min, const BigInt& max);
std::vector<BigInt> prime_factors(BigInt n);

int LegendreSymbol(int D, const BigInt& N);
bool CornacchiaSolve(const BigInt& N, int D, BigInt& a, BigInt& b);
bool SelectKandQ(const BigInt& m, BigInt& k, BigInt& q);

//algoritms
bool MillerRabinTestZero(BigInt& n, int iterations, BigInt& base, BigInt& nMinusOne, BigInt& power, BigInt& miniHelp, BigInt& d);
bool MillerRabinTest(BigInt& n, int iterations);
bool lucasLehmerTest(const BigInt& exponent);
std::vector<BigInt> sieveOfEratosthenes(const size_t limit);
std::vector<BigInt> sieveOfAtkin(const size_t limit);
bool LucasTest(BigInt& n, int iterations);
bool BPSWTest(BigInt& n, int iterations);
bool AKSPrimalityTest(const uint64_t n);
bool MillerTest(const uint64_t n);
bool ECPP(BigInt& n);

//random generators
void randomInRange(BigInt& out, const BigInt& min, const BigInt& max);
void LCG_fill(BigInt& out, size_t words);
BigInt LCG(size_t words = 1);
BigInt MersenneTwister(size_t words = 1);
BigInt Entropy(size_t words = 1);
BigInt generateRandomPrime(size_t size_in_bits = 1, size_t num_threads = 4);

double mean(const std::vector<BigInt>& nums);
double variance(const std::vector<BigInt>& nums, double m);
size_t uniqueCount(const std::vector<BigInt>& nums);

inline uint64_t getbmp(std::vector<uint8_t>& bmp, int idx) {
    return rand();
}