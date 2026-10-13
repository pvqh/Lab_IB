#pragma once
#include "BigInt.h"

template<class T>
inline T powmod(const T& base, const T& exponent, const T& modulus) {
    T baseCopy = base;
    T exponentCopy = exponent;
    T result = 1;
    baseCopy = baseCopy % modulus;

    while (exponentCopy > 0) {
        if ((exponentCopy & 1) == 1)
            result = mulmod(result, baseCopy, modulus);
        exponentCopy = exponentCopy >> 1;
        baseCopy = mulmod(baseCopy, baseCopy, modulus);
    }
    return result;
}

template<typename T>
inline T mulmod(const T& a, const T& b, const T& mod) {
    if constexpr (sizeof(T) <= 4) { 
        return (uint64_t(a) * b) % mod;
    } 
    else if constexpr(sizeof(T) <= 8) {
        return (__uint128_t(a) * b) % mod;
    }
    else {
        return (a * b) % mod;
    }
}

template<class T>
T integer_root(const T& n, uint64_t b) {
    if (b <= 1 || n <= T(1)) return n;
    T low = T(1);
    T high = n;
    T mid;
    while (low < high) {
        mid = (low + high + T(1)) / T(2);
        T p = T(1);
        for (uint64_t i = 0; i < b; ++i) {
            p *= mid;
            if (p > n) break;
        }
        if (p <= n)
            low = mid;
        else
            high = mid - T(1);
    }
    return low;
}

template<class T>
inline bool isPerfectPower(const T& n) {
    if (n <= 1) return false;
    uint64_t maxB;
    if constexpr (std::is_integral_v<T>) {
        double logn = std::log2((double)n);
        maxB = (uint64_t)std::ceil(logn);
    } else {
        maxB = 64;
    }

    for (uint64_t b = 2; b <= maxB; ++b) {
        T a = integer_root(n, b);
        if (a <= 1) continue;
        T p = 1;
        for (uint64_t i = 0; i < b; ++i) {
            p *= a;
            if (p > n) break;
        }
        if (p == n) return true;

        p = 1;
        for (uint64_t i = 0; i < b; ++i) {
            p *= (a + 1);
            if (p > n) break;
        }
        if (p == n) return true;
    }
    return false;
}

template<class T>
inline T MersenneMod(const T& x, const T& p) {
    T modMask = (T(1) << p) - 1;
    T low = x & modMask;
    T high = x >> p;
    T res = low + high;
    if (res >= modMask)
        res -= modMask;
    return res;
}

template<class T>
T normmod(const T& x, const T& m) {
    T r = x % m;
    if (r < T(0)) r = r + m;
    return r;
}

template<class T>
T sqrtmod(const T& n, const T& p) {
    if (p == 2) return n % p;
    if (powmod(n, (p - 1) / 2, p) != 1) return 0;
    if (p % 4 == 3) return powmod(n, (p + 1) / 4, p);

    T q = p - 1;
    T s = 0;
    while ((q % 2) == 0) {
        q /= 2;
        s += 1;
    }

    T z = 2;
    while (powmod(z, (p - 1) / 2, p) != p - 1)
        z += 1;

    T c = powmod(z, q, p);
    T x = powmod(n, (q + 1) / 2, p);
    T t = powmod(n, q, p);
    T m = s;

    while (t != 1) {
        T i = 0;
        T t2i = t;
        while (t2i != 1) {
            t2i = (t2i * t2i) % p;
            i += 1;
        }

        T exp = 1;
        for (T k = 0; k < m - i - 1; ++k)
            exp *= 2;

        T b = powmod(c, exp, p);

        x = (x * b) % p;
        t = (t * b * b) % p;
        c = (b * b) % p;
        m = i;
    }
    return x;
}

template<class T>
T inverseMod(T a, T m) {
    T m0 = m;
    T x0 = 0, x1 = 1;

    if (m == 1) return 0;

    while (a > 1) {
        T q = a / m;
        T t = m;

        m = a % m;
        a = t;

        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0) x1 += m0;

    return x1;
}

template<class T>
bool inverseModWithFactor(const T& a, const T& m, T& inv, T& factor) {
    inv = inverseMod(a % m, m);
    if (inv == 0) {
        factor = a.gcd(m);
        if (factor == 1 || factor == m) return true;
        return false;
    }
    return true;
}