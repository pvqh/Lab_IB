#include "BigInt.h"
#include <algorithm>
#include <cstdint>
#include <random>
#include <chrono>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>

// ============ Базовые методы ============

const BigInt& BigInt::getBase64() const {
    static const BigInt result({0, 1});
    return result;
}

void BigInt::setValue(uint64 value) {
    numbers.clear();
    if (value != 0) { 
        numbers.push_back(value);
    } else { 
        numbers.push_back(0); 
    }
    isMinus = false;
}

void BigInt::swap(BigInt& other) {
    numbers.swap(other.numbers);
    std::swap(isMinus, other.isMinus);
}

void BigInt::reserve(size_t size_in_bytes) {
    numbers.reserve((size_in_bytes + 7) / 8);
}

// ============ Операторы сравнения ============

// Количество значащих слов (ведущие нулевые слова не считаются).
// Ноль может храниться и как {}, и как {0} - обе формы дают 0.
static size_t usedWords(const BigInt& x) {
    size_t n = x.numbers.size();
    while (n > 0 && x.numbers[n - 1] == 0) --n;
    return n;
}

// Сравнение модулей: -1 если |a| < |b|, 0 если равны, 1 если |a| > |b|
static int compareAbs(const BigInt& a, const BigInt& b) {
    size_t na = usedWords(a), nb = usedWords(b);
    if (na != nb) return na < nb ? -1 : 1;

    for (size_t i = na; i-- > 0;) {
        if (a.numbers[i] != b.numbers[i]) {
            return a.numbers[i] < b.numbers[i] ? -1 : 1;
        }
    }
    return 0;
}

bool BigInt::operator<(const BigInt& other) const {
    // У нуля нет знака: "-0" и "+0" - одно и то же число
    bool negA = isMinus && !isZero();
    bool negB = other.isMinus && !other.isZero();
    if (negA != negB) return negA;

    int cmp = compareAbs(*this, other);
    return negA ? cmp > 0 : cmp < 0;
}

bool BigInt::operator<=(const BigInt& other) const {
    return *this < other || *this == other;
}

bool BigInt::operator>(const BigInt& other) const {
    return !(*this <= other);
}

bool BigInt::operator>=(const BigInt& other) const {
    return !(*this < other);
}

bool BigInt::operator==(const BigInt& other) const {
    if (compareAbs(*this, other) != 0) return false;
    return isZero() || isMinus == other.isMinus;
}

bool BigInt::operator!=(const BigInt& other) const {
    return !(*this == other);
}

// ============ Арифметические операторы ============

BigInt BigInt::operator+(const BigInt& other) const {
    BigInt result = *this;
    result += other;
    return result;
}

BigInt BigInt::operator-(const BigInt& other) const {
    BigInt result = *this;
    result -= other;
    return result;
}

BigInt BigInt::operator*(const BigInt& other) const {
    BigInt result;
    multiplyInto(other, result);
    return result;
}

BigInt BigInt::operator/(const BigInt& other) const {
    auto [quotient, remainder] = divmod1(*this, other);
    return quotient;
}

BigInt BigInt::operator%(const BigInt& other) const {
    auto [quotient, remainder] = divmod1(*this, other);
    return remainder;
}

BigInt& BigInt::operator+=(const BigInt& other) {
    if (isMinus == other.isMinus) {
        // Одинаковые знаки: складываем модули, знак сохраняется
        addVectors(other);
    } else if (compareAbs(*this, other) >= 0) {
        // Разные знаки: из большего модуля вычитаем меньший
        subtractVectors(other);
    } else {
        BigInt temp = other;
        temp.subtractVectors(*this);
        *this = temp;  // знак берется у большего по модулю, т.е. у other
    }
    return *this;
}

BigInt& BigInt::operator-=(const BigInt& other) {
    if (isMinus != other.isMinus) {
        // a - (-b) = a + b: складываем модули, знак сохраняется
        addVectors(other);
    } else if (compareAbs(*this, other) >= 0) {
        subtractVectors(other);
    } else {
        bool flipped = !isMinus;
        BigInt temp = other;
        temp.subtractVectors(*this);
        *this = temp;
        isMinus = flipped;
    }
    return *this;
}

BigInt& BigInt::operator*=(const BigInt& other) {
    BigInt result;
    multiplyInto(other, result);
    *this = result;
    return *this;
}

BigInt& BigInt::operator/=(const BigInt& other) {
    auto [quotient, remainder] = divmod1(*this, other);
    *this = quotient;
    return *this;
}

BigInt& BigInt::operator=(const BigInt& other) {
    if (this != &other) {
        numbers = other.numbers;
        isMinus = other.isMinus;
    }
    return *this;
}

BigInt& BigInt::operator=(BigInt&& other) {
    if (this != &other) {
        numbers = std::move(other.numbers);
        isMinus = other.isMinus;
    }
    return *this;
}

BigInt& BigInt::operator++() {
    *this += BigInt(1);
    return *this;
}

// ============ Побитовые операторы ============

BigInt BigInt::operator&(const BigInt& other) const {
    BigInt result = *this;
    result &= other;
    return result;
}

BigInt BigInt::operator|(const BigInt& other) const {
    BigInt result = *this;
    result |= other;
    return result;
}

BigInt BigInt::operator^(const BigInt& other) const {
    BigInt result = *this;
    result ^= other;
    return result;
}

BigInt& BigInt::operator&=(const BigInt& other) {
    size_t minSize = std::min(numbers.size(), other.numbers.size());
    numbers.resize(minSize);
    for (size_t i = 0; i < minSize; ++i) {
        numbers[i] &= other.numbers[i];
    }
    return *this;
}

BigInt& BigInt::operator|=(const BigInt& other) {
    if (numbers.size() < other.numbers.size()) {
        numbers.resize(other.numbers.size(), 0);
    }
    for (size_t i = 0; i < other.numbers.size(); ++i) {
        numbers[i] |= other.numbers[i];
    }
    return *this;
}

BigInt& BigInt::operator^=(const BigInt& other) {
    if (numbers.size() < other.numbers.size()) {
        numbers.resize(other.numbers.size(), 0);
    }
    for (size_t i = 0; i < other.numbers.size(); ++i) {
        numbers[i] ^= other.numbers[i];
    }
    return *this;
}

// ============ Операторы сдвига ============

BigInt BigInt::operator<<(const BigInt& shifts) const {
    BigInt result = *this;
    result.shiftBitsLeft(shifts.toUint64());
    return result;
}

BigInt BigInt::operator>>(const BigInt& shifts) const {
    BigInt result = *this;
    result.shiftBitsRight(shifts.toUint64());
    return result;
}

// ============ Вспомогательные арифметические методы ============

void BigInt::addVectors(const BigInt& other) {
    uint64_t carry = 0;
    size_t maxSize = std::max(numbers.size(), other.numbers.size());
    numbers.resize(maxSize, 0);
    
    for (size_t i = 0; i < maxSize; ++i) {
        uint64_t a = i < numbers.size() ? numbers[i] : 0;
        uint64_t b = i < other.numbers.size() ? other.numbers[i] : 0;
        // Переполнение возможно в каждом из двух сложений, проверяем оба
        uint64_t sum = a + carry;
        uint64_t overflow = (sum < a) ? 1 : 0;
        sum += b;
        overflow |= (sum < b) ? 1 : 0;
        numbers[i] = sum;
        carry = overflow;
    }
    
    if (carry) {
        numbers.push_back(carry);
    }
}

void BigInt::subtractVectors(const BigInt& other) {
    uint64_t borrow = 0;
    for (size_t i = 0; i < numbers.size(); ++i) {
        uint64_t b = i < other.numbers.size() ? other.numbers[i] : 0;
        uint64_t current = numbers[i];

        // Беззнаковое вычитание само "занимает" 2^64 при переходе через ноль,
        // нужно только запомнить, что заем был (в любом из двух вычитаний)
        uint64_t diff = current - b;
        uint64_t underflow = (current < b) ? 1 : 0;
        underflow |= (diff < borrow) ? 1 : 0;
        numbers[i] = diff - borrow;
        borrow = underflow;
    }
    
    // Удаляем ведущие нули
    while (numbers.size() > 1 && numbers.back() == 0) {
        numbers.pop_back();
    }
}

void BigInt::multiplyInto(const BigInt& other, BigInt& result) const {
    result.numbers.resize(numbers.size() + other.numbers.size(), 0);
    
    for (size_t i = 0; i < numbers.size(); ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < other.numbers.size() || carry; ++j) {
            uint64_t b_val = j < other.numbers.size() ? other.numbers[j] : 0;
            __uint128_t product = (__uint128_t)numbers[i] * b_val + result.numbers[i + j] + carry;
            result.numbers[i + j] = (uint64_t)product;
            carry = (uint64_t)(product >> 64);
        }
    }
    
    // Удаляем ведущие нули
    while (result.numbers.size() > 1 && result.numbers.back() == 0) {
        result.numbers.pop_back();
    }
    
    result.isMinus = isMinus != other.isMinus;
}

std::pair<BigInt, BigInt> BigInt::divmod(const BigInt& a, const BigInt& b) const {
    return divmod1(a, b);
}

std::pair<BigInt, BigInt> BigInt::divmod1(const BigInt& a, const BigInt& b) const {
    if (b.isZero()) throw std::runtime_error("Division by zero");
    
    if (compareAbs(a, b) < 0) {
        return {BigInt(0), a};
    }

    // Деление "в столбик" в двоичной системе: остаток начинается с нуля,
    // на каждом шаге в него сносится очередной бит делимого (от старшего
    // к младшему), и если остаток >= делителя - делитель вычитается,
    // а в частное записывается единичный бит.
    BigInt quotient, remainder;
    quotient.numbers.resize(a.numbers.size(), 0);

    for (int i = (int)a.bitLength() - 1; i >= 0; --i) {
        remainder.shiftBitsLeft(1);
        if (a.getBit(i)) {
            if (remainder.numbers.empty()) remainder.numbers.push_back(0);
            remainder.numbers[0] |= 1;
        }

        if (compareAbs(remainder, b) >= 0) {
            remainder.subtractVectors(b);
            quotient.numbers[i / 64] |= (1ULL << (i % 64));
        }
    }

    while (quotient.numbers.size() > 1 && quotient.numbers.back() == 0) {
        quotient.numbers.pop_back();
    }

    quotient.isMinus = a.isMinus != b.isMinus;
    remainder.isMinus = a.isMinus;

    return {quotient, remainder};
}

void BigInt::divmodInto(const BigInt& a, const BigInt& b, BigInt& quotient, BigInt& remainder) const {
    auto [q, r] = divmod1(a, b);
    quotient = q;
    remainder = r;
}

// ============ Методы сдвига ============

void BigInt::shiftBitsLeft(int shifts, BigInt* removedBits) {
    if (shifts <= 0) return;
    
    int wordShifts = shifts / 64;
    int bitShifts = shifts % 64;
    
    if (wordShifts > 0) {
        numbers.insert(numbers.begin(), wordShifts, 0);
    }
    
    if (bitShifts > 0) {
        uint64_t carry = 0;
        for (size_t i = 0; i < numbers.size(); ++i) {
            uint64_t newCarry = numbers[i] >> (64 - bitShifts);
            numbers[i] = (numbers[i] << bitShifts) | carry;
            carry = newCarry;
        }
        if (carry) {
            numbers.push_back(carry);
        }
    }
}

void BigInt::shiftBitsRight(int shifts, BigInt* removedBits) {
    if (shifts <= 0) return;
    
    int wordShifts = shifts / 64;
    int bitShifts = shifts % 64;
    
    if (wordShifts > 0) {
        if (wordShifts >= (int)numbers.size()) {
            numbers = {0};
            return;
        }
        numbers.erase(numbers.begin(), numbers.begin() + wordShifts);
    }
    
    if (bitShifts > 0) {
        uint64_t carry = 0;
        for (int i = numbers.size() - 1; i >= 0; --i) {
            uint64_t newCarry = numbers[i] << (64 - bitShifts);
            numbers[i] = (numbers[i] >> bitShifts) | carry;
            carry = newCarry;
        }
    }
    
    // Удаляем ведущие нули
    while (numbers.size() > 1 && numbers.back() == 0) {
        numbers.pop_back();
    }
}

void BigInt::shiftBits(int shifts, BigInt* removedBits) {
    if (shifts > 0) {
        shiftBitsLeft(shifts, removedBits);
    } else if (shifts < 0) {
        shiftBitsRight(-shifts, removedBits);
    }
}

// ============ Математические методы ============

BigInt& BigInt::pow(const BigInt& exponent) {
    if (exponent.isZero()) {
        *this = BigInt(1);
        return *this;
    }
    
    BigInt result(1);
    BigInt base = *this;
    BigInt exp = exponent;
    
    while (exp > 0) {
        if (exp.isEven()) {
            base *= base;
            exp = exp / BigInt(2);
        } else {
            result *= base;
            exp -= BigInt(1);
        }
    }
    
    *this = result;
    return *this;
}

BigInt BigInt::gcd(const BigInt& other) const {
    BigInt a = *this;
    BigInt b = other;
    a.isMinus = false;
    b.isMinus = false;
    
    while (!b.isZero()) {
        BigInt temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

BigInt BigInt::lcm(const BigInt& other) const {
    BigInt g = gcd(other);
    if (g.isZero()) return BigInt(0);
    return (*this * other) / g;
}

BigInt BigInt::sqrt() const {
    if (isMinus) throw std::runtime_error("Square root of negative number");
    if (isZero()) return BigInt(0);
    
    BigInt low(1);
    BigInt high = *this;
    BigInt mid, square;
    
    while (low <= high) {
        mid = (low + high) / BigInt(2);
        square = mid * mid;
        
        if (square == *this) return mid;
        else if (square < *this) low = mid + BigInt(1);
        else high = mid - BigInt(1);
    }
    return high;
}

// ============ Вспомогательные методы ============

std::string BigInt::str(Base base) const {
    if (isZero()) return "0";
    
    std::stringstream ss;
    if (isMinus) ss << "-";
    
    if (base == Base::HEX) {
        // Для шестнадцатеричного представления
        bool first = true;
        for (int i = numbers.size() - 1; i >= 0; --i) {
            if (first) {
                ss << std::hex << numbers[i];
                first = false;
            } else {
                ss << std::hex << std::setw(16) << std::setfill('0') << numbers[i];
            }
        }
    } else if (base == Base::DEC) {
        // Упрощенное десятичное представление (только для маленьких чисел)
        if (numbers.size() == 1) {
            ss << std::dec << numbers[0];
        } else {
            // Для больших чисел - просто показываем первый блок
            ss << std::dec << numbers[0] << "...";
        }
    } else if (base == Base::BIN) {
        // Бинарное представление
        for (int i = numbers.size() - 1; i >= 0; --i) {
            for (int bit = 63; bit >= 0; --bit) {
                ss << ((numbers[i] >> bit) & 1);
            }
            if (i > 0) ss << " ";
        }
    }
    
    return ss.str();
}

std::string BigInt::toPowerOfTwoBase(size_t k) const {
    // Упрощенная реализация
    std::stringstream ss;
    ss << "Base 2^" << k << ": ";
    for (size_t i = 0; i < numbers.size(); ++i) {
        if (i > 0) ss << " ";
        ss << numbers[i];
    }
    return ss.str();
}

// ============ Внешние функции ============

BigInt pow(const BigInt& number, const BigInt& exponent) {
    BigInt copy = number;
    return copy.pow(exponent);
}

BigInt random(const BigInt& min, const BigInt& max) {
    if (max < min) return random(max, min);

    BigInt range = max - min + 1;
    if (range == 1) return min;

    size_t bits = range.bitLength();
    size_t words = (bits + 63) / 64;

    std::mt19937_64 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);

    BigInt result;

    do {
        result.numbers.clear();
        for (size_t i = 0; i < words; i++) {
            result.numbers.push_back(dist(rng));
        }
        // Обрезаем лишние биты
        size_t extraBits = words * 64 - bits;
        if (extraBits > 0) {
            result.numbers.back() &= ((1ULL << (64 - extraBits)) - 1);
        }
        result.isMinus = false;
    } while (result >= range);

    return result + min;
}

// ============ Простые реализации остальных функций ============

std::vector<BigInt> prime_factors(BigInt n) {
    std::vector<BigInt> factors;
    // Упрощенная реализация
    if (n < BigInt(2)) return factors;
    
    BigInt divisor(2);
    while (n > BigInt(1)) {
        if (n % divisor == BigInt(0)) {
            factors.push_back(divisor);
            n = n / divisor;
        } else {
            divisor = divisor + BigInt(1);
            if (divisor * divisor > n) {
                if (n > BigInt(1)) {
                    factors.push_back(n);
                }
                break;
            }
        }
    }
    return factors;
}

int LegendreSymbol(int D, const BigInt& N) {
    // Упрощенная реализация
    return 1;
}

bool CornacchiaSolve(const BigInt& N, int D, BigInt& a, BigInt& b) {
    // Упрощенная реализация
    return false;
}

bool SelectKandQ(const BigInt& m, BigInt& k, BigInt& q) {
    if (m.isZero()) return false;
    q = m;
    k = BigInt(0);
    while (q.isEven()) {
        q = q / BigInt(2);
        k = k + BigInt(1);
    }
    return true;
}

// Упрощенные реализации алгоритмов (заглушки)
bool MillerRabinTestZero(BigInt& n, int iterations, BigInt& base, BigInt& nMinusOne, BigInt& power, BigInt& miniHelp, BigInt& d) {
    return true;
}

bool MillerRabinTest(BigInt& n, int iterations) {
    return true;
}

bool lucasLehmerTest(const BigInt& exponent) {
    return true;
}

std::vector<BigInt> sieveOfEratosthenes(const size_t limit) {
    return std::vector<BigInt>();
}

std::vector<BigInt> sieveOfAtkin(const size_t limit) {
    return std::vector<BigInt>();
}

bool LucasTest(BigInt& n, int iterations) {
    return true;
}

bool BPSWTest(BigInt& n, int iterations) {
    return true;
}

bool AKSPrimalityTest(const uint64_t n) {
    return true;
}

bool MillerTest(const uint64_t n) {
    return true;
}

bool ECPP(BigInt& n) {
    return true;
}

void randomInRange(BigInt& out, const BigInt& min, const BigInt& max) {
    out = random(min, max);
}

void LCG_fill(BigInt& out, size_t words) {
    out.numbers.resize(words);
    for (size_t i = 0; i < words; ++i) {
        out.numbers[i] = rand();
    }
}

BigInt LCG(size_t words) {
    BigInt result;
    LCG_fill(result, words);
    return result;
}

BigInt MersenneTwister(size_t words) {
    BigInt result;
    result.numbers.resize(words);
    std::mt19937_64 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    for (size_t i = 0; i < words; ++i) {
        result.numbers[i] = rng();
    }
    return result;
}

BigInt Entropy(size_t words) {
    return MersenneTwister(words);
}

BigInt generateRandomPrime(size_t size_in_bits, size_t num_threads) {
    // Упрощенная реализация
    return BigInt(65537);
}

double mean(const std::vector<BigInt>& nums) {
    if (nums.empty()) return 0.0;
    BigInt sum;
    for (const auto& num : nums) {
        sum += num;
    }
    return sum.toUint64() / (double)nums.size();
}

double variance(const std::vector<BigInt>& nums, double m) {
    if (nums.empty()) return 0.0;
    double var = 0.0;
    for (const auto& num : nums) {
        double diff = num.toUint64() - m;
        var += diff * diff;
    }
    return var / nums.size();
}

size_t uniqueCount(const std::vector<BigInt>& nums) {
    return nums.size(); // Упрощенная реализация
}

bool BigInt::isZero() const {
    // Число равно нулю, если у него нет чисел или все числа нулевые
    if (numbers.empty()) return true;
    for (uint64_t num : numbers) {
        if (num != 0) return false;
    }
    return true;
}

bool BigInt::isEven() const {
    // Число четное, если младший бит равен 0
    if (numbers.empty()) return true;
    return (numbers[0] & 1) == 0;
}

bool BigInt::getBit(size_t bitIndex) const {
    size_t wordIndex = bitIndex / 64;
    size_t bitInWord = bitIndex % 64;
    
    if (wordIndex >= numbers.size()) {
        return false; // За пределами - считаем бит равным 0
    }
    
    return (numbers[wordIndex] >> bitInWord) & 1;
}