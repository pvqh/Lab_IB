#include <iostream>
#include <cmath>
#include <stdexcept>
#include <string>
#include <vector>

class RSA {
private:
    long long p, q, n, phi, e, d;
    
    bool isPrime(long long num) {
        if (num <= 1) return false;
        if (num <= 3) return true;
        if (num % 2 == 0 || num % 3 == 0) return false;
        
        for (long long i = 5; i * i <= num; i += 6) {
            if (num % i == 0 || num % (i + 2) == 0)
                return false;
        }
        return true;
    }
    
    long long gcd(long long a, long long b) {
        while (b != 0) {
            long long temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }
    
    long long extendedGCD(long long a, long long b, long long& x, long long& y) {
        if (b == 0) {
            x = 1;
            y = 0;
            return a;
        }
        long long x1, y1;
        long long gcd = extendedGCD(b, a % b, x1, y1);
        x = y1;
        y = x1 - (a / b) * y1;
        return gcd;
    }
    
    long long modPow(long long base, long long exp, long long mod) {
        long long result = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2 == 1)
                result = (result * base) % mod;
            exp = exp >> 1;
            base = (base * base) % mod;
        }
        return result;
    }

    // How many bytes of text fit in one block so that the block is always < n
    int blockSize() {
        int size = 0;
        for (long long limit = 256; limit <= n; limit *= 256)
            size++;
        return size;
    }

public:
    RSA() : p(0), q(0), n(0), phi(0), e(0), d(0) {}
    
    void generateKeys(long long prime1, long long prime2) {
        if (!isPrime(prime1) || !isPrime(prime2)) {
            throw std::invalid_argument("Both numbers must be prime");
        }
        
        if (prime1 == prime2) {
            throw std::invalid_argument("Prime numbers must be different");
        }
        
        p = prime1;
        q = prime2;
        n = p * q;
        phi = (p - 1) * (q - 1);
        
        e = 65537;
        if (e >= phi || gcd(e, phi) != 1) {
            for (e = 3; e < phi; e += 2) {
                if (gcd(e, phi) == 1) break;
            }
        }
        
        long long x, y;
        extendedGCD(e, phi, x, y);
        d = (x % phi + phi) % phi;
    }
    
    long long encrypt(long long message) {
        if (n == 0) {
            throw std::runtime_error("Keys not generated. Call generateKeys() first.");
        }
        if (message >= n) {
            throw std::invalid_argument("Message must be less than n");
        }
        return modPow(message, e, n);
    }
    
    long long decrypt(long long ciphertext) {
        if (n == 0) {
            throw std::runtime_error("Keys not generated. Call generateKeys() first.");
        }
        return modPow(ciphertext, d, n);
    }

    // Splits text into blocks and packs the bytes of each block into one number
    std::vector<long long> textToNumbers(const std::string& text) {
        if (n == 0) {
            throw std::runtime_error("Keys not generated. Call generateKeys() first.");
        }
        int size = blockSize();
        if (size == 0) {
            throw std::runtime_error("n is too small to hold a character (need n >= 256)");
        }

        std::vector<long long> numbers;
        for (size_t i = 0; i < text.size(); i += size) {
            long long value = 0;
            for (size_t j = i; j < i + size && j < text.size(); j++)
                value = value * 256 + (unsigned char)text[j];
            numbers.push_back(value);
        }
        return numbers;
    }

    std::string numbersToText(const std::vector<long long>& numbers) {
        std::string text;
        for (long long value : numbers) {
            std::string block;
            while (value > 0) {
                block.insert(block.begin(), (char)(value % 256));
                value /= 256;
            }
            text += block;
        }
        return text;
    }

    std::vector<long long> encryptText(const std::string& text) {
        std::vector<long long> numbers = textToNumbers(text);
        for (long long& number : numbers)
            number = encrypt(number);
        return numbers;
    }

    std::string decryptText(const std::vector<long long>& ciphertext) {
        std::vector<long long> numbers;
        for (long long number : ciphertext)
            numbers.push_back(decrypt(number));
        return numbersToText(numbers);
    }

    void printKeys() {
        std::cout << "=== RSA Key Information ===" << std::endl;
        std::cout << "Prime p: " << p << std::endl;
        std::cout << "Prime q: " << q << std::endl;
        std::cout << "Modulus n: " << n << std::endl;
        std::cout << "Phi(n): " << phi << std::endl;
        std::cout << "Public Key (e, n): (" << e << ", " << n << ")" << std::endl;
        std::cout << "Private Key (d, n): (" << d << ", " << n << ")" << std::endl;
        std::cout << "===========================" << std::endl;
    }

    void printResult(const std::string& msg){
        std::cout << "Original message: " << msg << std::endl;

        std::cout << "As numbers:";
        for (long long number : this->textToNumbers(msg))
            std::cout << " " << number;
        std::cout << std::endl;

        std::vector<long long> encrypted = this->encryptText(msg);
        std::cout << "Encrypted:";
        for (long long number : encrypted)
            std::cout << " " << number;
        std::cout << std::endl;

        std::string decrypted = this->decryptText(encrypted);
        std::cout << "Decrypted: " << decrypted << std::endl;

        if (msg == decrypted) {
            std::cout << "Status: SUCCESS" << std::endl;
        } else {
            std::cout << "Status: FAILED" << std::endl;
        }
    }
};

void testRSA() {
    std::cout << "========================================" << std::endl;
    std::cout << "      RSA Encryption/Decryption Test" << std::endl;
    std::cout << "========================================" << std::endl << std::endl;
    
    RSA rsa;
    
    long long p = 61;
    long long q = 53;
    
    std::cout << "Generating RSA keys with primes p=" << p << " and q=" << q << std::endl << std::endl;
    
    try {

        // *********** TESTING WITH SMALL PRIMES **********
        std::cout << "=== Encryption/Decryption Tests ===" << std::endl;
        rsa.generateKeys(p, q);
        rsa.printKeys();
        std::string messages[] = {"Hello", "RSA", "Meet me at 9 pm.", "Attack at dawn!"};

        for (int i = 0; i < 4; i++) {
            std::string message = messages[i];

            std::cout << "\nTest " << (i + 1) << ":" << std::endl;
            rsa.printResult(message);
        }

        // ********** TESTING WITH LARGER PRIMES **********
        std::cout << "\n=== Testing with larger primes ===" << std::endl;
        RSA rsa2;
        rsa2.generateKeys(32771, 31531);
        rsa2.printKeys();
        std::string msg = "The quick brown fox jumps over the lazy dog";
        rsa2.printResult(msg);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    // ********** TESTING WITH USER'S INPUT **********
    try {
        std::cout << "\n=== Testing with user's input ===" << std::endl;
        RSA rsa3;
        rsa3.generateKeys(32771, 31531);
        rsa3.printKeys();
        std::string msg = "";
        std::cout << "Enter a message to encrypt: ";
        std::getline(std::cin, msg);
        rsa3.printResult(msg);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    std::cout << "\n========================================" << std::endl;


}

int main() {
    testRSA();
    return 0;
}