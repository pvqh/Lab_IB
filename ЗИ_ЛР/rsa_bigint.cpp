// RSA on BigInt: key generation, encryption, decryption.
// Implements the RSA part of cryptography.h.
//
// This is "textbook" RSA: raw m^e mod n with no padding (no OAEP / PSS).

// windows.h must come before BigInt.h: BigInt.h does `using namespace std`,
// and the Windows headers do not compile cleanly after that.
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <cstdio>
#endif

#include "cryptography.h"
#include <chrono>
#include <iostream>
#include <stdexcept>

bool rsaVerbose = false;

// ============ Randomness ============

// Fills the buffer with bytes from the operating system's cryptographic
// generator. rand() and mt19937 are predictable, and a predictable prime
// means a broken key, so they must not be used here.
static void secureRandomBytes(uint8_t* buffer, size_t length) {
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, buffer, (ULONG)length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptGenRandom failed");
    }
#else
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom == nullptr) {
        throw std::runtime_error("Cannot open /dev/urandom");
    }
    size_t got = fread(buffer, 1, length, urandom);
    fclose(urandom);
    if (got != length) {
        throw std::runtime_error("Cannot read /dev/urandom");
    }
#endif
}

// Random number in [0, 2^bits)
static BigInt randomBits(size_t bits) {
    BigInt result;
    if (bits == 0) return result;

    size_t words = (bits + 63) / 64;
    result.numbers.resize(words);
    secureRandomBytes((uint8_t*)result.numbers.data(), words * 8);

    // Clear the bits above `bits` in the top word
    size_t extraBits = words * 64 - bits;
    if (extraBits > 0) {
        result.numbers.back() &= (~0ULL >> extraBits);
    }
    return result;
}

// ============ Montgomery arithmetic ============

// Modular exponentiation is a long chain of "multiply, then reduce mod n".
// The multiplication is cheap; the reduction is a division, and division is
// the slow part. Montgomery's method replaces that division with a second
// multiplication.
//
// Let R = 2^(64k), where k is the number of 64-bit words in n. A number x is
// kept in "Montgomery form" x' = x*R mod n. For two numbers in that form
//
//     montMul(a', b') = a' * b' / R mod n = (a*b)*R mod n = (a*b)'
//
// so the product is again in Montgomery form. Dividing by R is free (drop the
// low k words) as long as those low words are zero, and they can always be
// made zero by adding a suitable multiple of n, which does not change the
// value mod n. That multiple is found one word at a time with nPrime.
//
// Requires n to be odd, which every RSA modulus and every prime candidate is.
class Montgomery {
public:
    explicit Montgomery(const BigInt& modulus);

    // base^exponent mod n
    BigInt pow(const BigInt& base, const BigInt& exponent) const;
    // a*b mod n
    BigInt mul(const BigInt& a, const BigInt& b) const;

private:
    typedef std::vector<uint64> Words;  // same word type as BigInt::numbers

    void montMul(const Words& a, const Words& b, Words& out) const;
    Words toMont(const BigInt& x) const;
    BigInt fromMont(const Words& x) const;

    BigInt n;
    size_t k;           // words in n
    Words nWords;       // n as exactly k words
    uint64_t nPrime;    // -n^(-1) mod 2^64
    Words r2;           // R^2 mod n, used to convert into Montgomery form
};

Montgomery::Montgomery(const BigInt& modulus): n(modulus) {
    if (n.isEven() || n <= BigInt(1)) {
        throw std::invalid_argument("Montgomery: modulus must be odd and greater than 1");
    }

    k = (n.bitLength() + 63) / 64;
    nWords = n.numbers;
    nWords.resize(k, 0);

    // Inverse of n[0] mod 2^64 by Newton's iteration: each step doubles the
    // number of correct low bits. For odd x, x*x = 1 (mod 8), so x itself is
    // a correct inverse in 3 bits; 5 steps give 96 >= 64.
    uint64_t inverse = nWords[0];
    for (int i = 0; i < 5; ++i) {
        inverse *= 2 - nWords[0] * inverse;
    }
    nPrime = 0 - inverse;

    BigInt rSquared = (BigInt(1) << BigInt((uint64)(128 * k))) % n;
    r2 = rSquared.numbers;
    r2.resize(k, 0);
}

// out = a * b / R mod n. a and b must be < n; out may alias a or b.
void Montgomery::montMul(const Words& a, const Words& b, Words& out) const {
    Words t(k + 2, 0);

    for (size_t i = 0; i < k; ++i) {
        // t += a * b[i]
        uint64_t carry = 0;
        for (size_t j = 0; j < k; ++j) {
            __uint128_t cur = (__uint128_t)a[j] * b[i] + t[j] + carry;
            t[j] = (uint64_t)cur;
            carry = (uint64_t)(cur >> 64);
        }
        __uint128_t top = (__uint128_t)t[k] + carry;
        t[k] = (uint64_t)top;
        t[k + 1] = (uint64_t)(top >> 64);

        // Pick m so that the lowest word of t + m*n is zero, then add m*n
        // and shift t right by one word (that is the division by 2^64).
        uint64_t m = t[0] * nPrime;
        __uint128_t cur = (__uint128_t)m * nWords[0] + t[0];
        carry = (uint64_t)(cur >> 64);
        for (size_t j = 1; j < k; ++j) {
            cur = (__uint128_t)m * nWords[j] + t[j] + carry;
            t[j - 1] = (uint64_t)cur;
            carry = (uint64_t)(cur >> 64);
        }
        top = (__uint128_t)t[k] + carry;
        t[k - 1] = (uint64_t)top;
        t[k] = t[k + 1] + (uint64_t)(top >> 64);
    }

    // Now t < 2n, so at most one subtraction of n is needed
    bool needSubtract = t[k] != 0;
    if (!needSubtract) {
        needSubtract = true;  // t == n also has to be reduced
        for (size_t i = k; i-- > 0;) {
            if (t[i] != nWords[i]) {
                needSubtract = t[i] > nWords[i];
                break;
            }
        }
    }
    if (needSubtract) {
        uint64_t borrow = 0;
        for (size_t i = 0; i < k; ++i) {
            uint64_t diff = t[i] - nWords[i];
            uint64_t underflow = (t[i] < nWords[i]) ? 1 : 0;
            underflow |= (diff < borrow) ? 1 : 0;
            t[i] = diff - borrow;
            borrow = underflow;
        }
    }

    t.resize(k);
    out.swap(t);
}

// x -> x*R mod n. montMul(x, R^2) = x * R^2 / R = x*R.
Montgomery::Words Montgomery::toMont(const BigInt& x) const {
    BigInt reduced = (x >= n) ? x % n : x;
    Words words = reduced.numbers;
    words.resize(k, 0);
    montMul(words, r2, words);
    return words;
}

// x*R mod n -> x. montMul(x', 1) = x' / R.
BigInt Montgomery::fromMont(const Words& x) const {
    Words one(k, 0);
    one[0] = 1;

    BigInt result;
    montMul(x, one, result.numbers);
    while (result.numbers.size() > 1 && result.numbers.back() == 0) {
        result.numbers.pop_back();
    }
    return result;
}

BigInt Montgomery::mul(const BigInt& a, const BigInt& b) const {
    Words x = toMont(a);
    Words y = toMont(b);
    montMul(x, y, x);
    return fromMont(x);
}

// Square-and-multiply, reading the exponent from its top bit down:
// for every bit square the result, and if the bit is 1 also multiply by base.
// Example: exponent 13 = 1101b gives ((b^2 * b)^2)^2 * b = b^13.
BigInt Montgomery::pow(const BigInt& base, const BigInt& exponent) const {
    if (exponent.isZero()) {
        return BigInt(1);
    }

    Words x = toMont(base);
    Words result = x;  // accounts for the top bit of the exponent

    for (size_t i = exponent.bitLength() - 1; i-- > 0;) {
        montMul(result, result, result);
        if (exponent.getBit(i)) {
            montMul(result, x, result);
        }
    }
    return fromMont(result);
}

// ============ Primality testing ============

// Odd primes below 100000, by the sieve of Eratosthenes
static const std::vector<uint32_t>& smallPrimes() {
    static const std::vector<uint32_t> primes = [] {
        const uint32_t limit = 100000;
        std::vector<bool> composite(limit, false);
        std::vector<uint32_t> result;
        for (uint32_t i = 3; i < limit; i += 2) {
            if (composite[i]) continue;
            result.push_back(i);
            for (uint64_t j = (uint64_t)i * i; j < limit; j += 2 * i) {
                composite[j] = true;
            }
        }
        return result;
    }();
    return primes;
}

// value mod divisor for a small divisor, one word at a time (no BigInt division)
static uint32_t modSmall(const BigInt& value, uint32_t divisor) {
    uint64_t remainder = 0;
    for (size_t i = value.numbers.size(); i-- > 0;) {
        __uint128_t cur = ((__uint128_t)remainder << 64) | value.numbers[i];
        remainder = (uint64_t)(cur % divisor);
    }
    return (uint32_t)remainder;
}

// Fermat test with base 2: for prime n, 2^(n-1) = 1 (mod n).
// A different result proves n composite. Result 1 only makes n a candidate.
static bool passesFermat(const Montgomery& mont, const BigInt& n) {
    return mont.pow(BigInt(2), n - BigInt(1)) == BigInt(1);
}

// Miller-Rabin. Write n-1 = 2^s * d with d odd. For prime n and any base a,
// the sequence a^d, a^(2d), a^(4d), ..., a^(2^s * d) ends in 1, and the only
// square roots of 1 mod a prime are 1 and n-1. So either a^d = 1, or n-1
// appears somewhere before the end. If neither happens, n is composite.
// A composite n survives one random base with probability at most 1/4.
static bool passesMillerRabin(const Montgomery& mont, const BigInt& n, int rounds) {
    BigInt nMinusOne = n - BigInt(1);
    BigInt d = nMinusOne;
    size_t s = 0;
    while (d.isEven()) {
        d.shiftBitsRight(1);
        ++s;
    }

    for (int round = 0; round < rounds; ++round) {
        // Random base in [2, n-2]: one bit shorter than n, so always below n-1
        BigInt a;
        do {
            a = randomBits(n.bitLength() - 1);
        } while (a < BigInt(2));

        BigInt x = mont.pow(a, d);
        if (x == BigInt(1) || x == nMinusOne) continue;

        bool reachedMinusOne = false;
        for (size_t i = 1; i < s; ++i) {
            x = mont.mul(x, x);
            if (x == nMinusOne) {
                reachedMinusOne = true;
                break;
            }
            if (x == BigInt(1)) break;  // a square root of 1 other than n-1
        }
        if (!reachedMinusOne) return false;
    }
    return true;
}

// ============ Prime generation ============

static const int MILLER_RABIN_ROUNDS = 5;

// Random prime p of exactly `bits` bits with gcd(p-1, e) = 1.
//
// Starts from a random odd number and walks upwards in steps of 2. The cheap
// filters run first, so the expensive ones see as few candidates as possible:
//   1. sieve    - is it divisible by a small prime?
//   2. gcd      - is p-1 coprime to e? (otherwise d does not exist)
//   3. Fermat   - one exponentiation, rejects almost every composite
//   4. Miller-Rabin - confirms the survivor
static BigInt generatePrime(size_t bits, const BigInt& e, const char* label) {
    const std::vector<uint32_t>& primes = smallPrimes();
    auto startTime = std::chrono::steady_clock::now();
    size_t scanned = 0, tested = 0;

    while (true) {
        BigInt candidate = randomBits(bits);
        // Top two bits set: p, q >= 1.5 * 2^(bits-1), so p*q has exactly
        // 2*bits bits. Low bit set: odd.
        candidate.numbers[(bits - 1) / 64] |= 1ULL << ((bits - 1) % 64);
        candidate.numbers[(bits - 2) / 64] |= 1ULL << ((bits - 2) % 64);
        candidate.numbers[0] |= 1;

        // Remainders of the starting point by every small prime. Moving to
        // candidate + 2 just adds 2 to each, so the big number is divided
        // only once per starting point.
        std::vector<uint32_t> remainders(primes.size());
        for (size_t i = 0; i < primes.size(); ++i) {
            remainders[i] = modSmall(candidate, primes[i]);
        }

        // If the walk ever runs past 2^bits, pick a new starting point
        while (candidate.bitLength() == bits) {
            ++scanned;

            bool hasSmallFactor = false;
            for (size_t i = 0; i < primes.size(); ++i) {
                if (remainders[i] == 0) {
                    hasSmallFactor = true;
                    break;
                }
            }

            if (!hasSmallFactor && (candidate - BigInt(1)).gcd(e) == BigInt(1)) {
                ++tested;
                if (rsaVerbose) {
                    std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - startTime;
                    std::cerr << "[" << label << "] testing candidate " << tested
                              << " (" << scanned << " scanned, " << elapsed.count() << " s)" << std::endl;
                }

                Montgomery mont(candidate);
                if (passesFermat(mont, candidate) && passesMillerRabin(mont, candidate, MILLER_RABIN_ROUNDS)) {
                    if (rsaVerbose) {
                        std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - startTime;
                        std::cerr << "[" << label << "] prime found (" << elapsed.count() << " s)" << std::endl;
                    }
                    return candidate;
                }
            }

            candidate += BigInt(2);
            for (size_t i = 0; i < primes.size(); ++i) {
                remainders[i] += 2;
                if (remainders[i] >= primes[i]) remainders[i] -= primes[i];
            }
        }
    }
}

// ============ RSA ============

RSAKeyPair rsaGenerateKeys(size_t bits, const BigInt& e_in) {
    // Below 64 bits the primes would be smaller than the sieve bound
    if (bits < 64) {
        throw std::invalid_argument("RSA: key size must be at least 64 bits");
    }
    if (e_in.isMinus || e_in.isEven() || e_in < BigInt(3)) {
        throw std::invalid_argument("RSA: e must be odd and at least 3");
    }

    size_t pBits = bits / 2;
    size_t qBits = bits - pBits;

    BigInt p = generatePrime(pBits, e_in, "p");
    BigInt q;
    do {
        q = generatePrime(qBits, e_in, "q");
    } while (q == p);

    BigInt n = p * q;
    BigInt phi = (p - BigInt(1)) * (q - BigInt(1));

    // d is the inverse of e mod phi: e*d = 1 + k*phi. It exists because
    // generatePrime guaranteed gcd(e, p-1) = gcd(e, q-1) = 1.
    BigInt d = inverseMod(e_in, phi);
    if ((e_in * d) % phi != BigInt(1)) {
        throw std::runtime_error("RSA: failed to compute private exponent");
    }

    return RSAKeyPair{n, e_in, d};
}

// c = m^e mod n
BigInt rsaEncrypt(const BigInt& message, const BigInt& e, const BigInt& n) {
    if (message.isMinus || message >= n) {
        throw std::invalid_argument("RSA: message must be in range [0, n)");
    }
    return Montgomery(n).pow(message, e);
}

// m = c^d mod n
BigInt rsaDecrypt(const BigInt& message, const BigInt& d, const BigInt& n) {
    if (message.isMinus || message >= n) {
        throw std::invalid_argument("RSA: ciphertext must be in range [0, n)");
    }
    return Montgomery(n).pow(message, d);
}
