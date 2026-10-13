#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include "BigInt.h"
#include "cryptography.h"

// Packs the bytes of a text into one number (first character = highest byte)
BigInt textToNumber(const std::string& text) {
    static const char* digits = "0123456789abcdef";
    std::string hex;
    for (unsigned char c : text) {
        hex += digits[c >> 4];
        hex += digits[c & 15];
    }
    return BigInt(hex.c_str());
}

std::string numberToText(const BigInt& number) {
    std::string hex = number.str(Base::HEX);
    if (hex.size() % 2 != 0) hex = "0" + hex;

    std::string text;
    for (size_t i = 0; i < hex.size(); i += 2) {
        text += (char)std::stoi(hex.substr(i, 2), nullptr, 16);
    }
    return text;
}

bool check(const std::string& name, bool passed) {
    std::cout << "  " << name << ": " << (passed ? "OK" : "FAILED") << std::endl;
    return passed;
}

// Generates a key of the given size and checks that it actually works
bool testRSA(size_t bits) {
    bool ok = true;

    // The classic textbook example: p = 61, q = 53
    std::cout << "Known-answer test (n = 3233, e = 17, d = 2753):" << std::endl;
    BigInt smallN(3233), smallE(17), smallD(2753);
    ok &= check("65^17 mod 3233 == 2790", rsaEncrypt(BigInt(65), smallE, smallN) == BigInt(2790));
    ok &= check("2790^2753 mod 3233 == 65", rsaDecrypt(BigInt(2790), smallD, smallN) == BigInt(65));

    std::cout << "\nGenerating a " << bits << "-bit key..." << std::endl;
    auto start = std::chrono::steady_clock::now();
    RSAKeyPair key = rsaGenerateKeys(bits);
    std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - start;
    std::cout << "  done in " << elapsed.count() << " s" << std::endl;
    std::cout << "  n = " << key.n.str(Base::HEX) << std::endl;
    std::cout << "  e = " << key.e.str(Base::HEX) << std::endl;
    std::cout << "  d = " << key.d.str(Base::HEX) << std::endl;
    ok &= check("n has exactly " + std::to_string(bits) + " bits", key.n.bitLength() == bits);

    std::cout << "\nEncryption round trip:" << std::endl;
    std::string text = "Attack at dawn!";
    BigInt message = textToNumber(text);
    BigInt ciphertext = rsaEncrypt(message, key.e, key.n);
    BigInt decrypted = rsaDecrypt(ciphertext, key.d, key.n);
    std::cout << "  message    = " << text << std::endl;
    std::cout << "  ciphertext = " << ciphertext.str(Base::HEX) << std::endl;
    std::cout << "  decrypted  = " << numberToText(decrypted) << std::endl;
    ok &= check("ciphertext differs from message", ciphertext != message);
    ok &= check("decrypt(encrypt(m)) == m", decrypted == message);

    // A signature is the same operation with the keys swapped
    std::cout << "\nSignature round trip:" << std::endl;
    BigInt signature = rsaDecrypt(message, key.d, key.n);
    ok &= check("verify(sign(m)) == m", rsaEncrypt(signature, key.e, key.n) == message);

    std::cout << "\nInput validation:" << std::endl;
    bool rejected = false;
    try {
        rsaEncrypt(key.n, key.e, key.n);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    ok &= check("message >= n is rejected", rejected);

    std::cout << "\n" << (ok ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << std::endl;
    return ok;
}

// Generates a key and writes it as hex to <prefix>.n, <prefix>.e, <prefix>.d
bool generateKeyFiles(size_t bits, const std::string& prefix) {
    rsaVerbose = true;
    RSAKeyPair key = rsaGenerateKeys(bits);

    const std::pair<const char*, const BigInt*> parts[] = {{".n", &key.n}, {".e", &key.e}, {".d", &key.d}};
    for (const auto& [extension, value] : parts) {
        std::ofstream file(prefix + extension);
        file << value->str(Base::HEX) << "\n";
        if (!file) {
            std::cerr << "Error: cannot write " << prefix << extension << std::endl;
            return false;
        }
    }

    std::cout << "Wrote " << prefix << ".n, " << prefix << ".e, " << prefix << ".d ("
              << key.n.bitLength() << "-bit modulus)" << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    try {
        std::string command = argc > 1 ? argv[1] : "test";

        if (command == "test" && argc <= 3) {
            size_t bits = argc > 2 ? std::stoul(argv[2]) : 512;
            return testRSA(bits) ? 0 : 1;
        }
        if (command == "keygen" && argc == 4) {
            return generateKeyFiles(std::stoul(argv[2]), argv[3]) ? 0 : 1;
        }

        std::cerr << "Usage:\n"
                  << "  rsa_app test [bits]            generate a key and test it (default 512)\n"
                  << "  rsa_app keygen <bits> <prefix> write <prefix>.n, <prefix>.e, <prefix>.d\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
