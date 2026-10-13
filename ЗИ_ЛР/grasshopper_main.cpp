#include <iostream>
#include "BigInt.h"
#include "cryptography.h"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
void testGrasshopper() {
    std::cout << "=== Тестирование Grasshopper ===\n\n";
    
    // Тестовые данные из ГОСТ
    BigInt key("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
    BigInt plaintext("1122334455667700ffeeddccbbaa9988");
    BigInt expected_ciphertext("7f679d90bebc24305a468d42b9d4edcd");
    
    std::cout << "Ключ: " << key.str(Base::HEX) << "\n";
    std::cout << "Открытый текст: " << plaintext.str(Base::HEX) << "\n";
    std::cout << "Ожидаемый шифртекст: " << expected_ciphertext.str(Base::HEX) << "\n\n";
    
    std::cout << "Шифрование... ";
    BigInt ciphertext = grasshopperCode(plaintext, key);
    std::cout << "Готово\n";
    std::cout << "Полученный шифртекст: " << ciphertext.str(Base::HEX) << "\n";
    
    if (ciphertext == expected_ciphertext) {
        std::cout << "✓ Шифрование успешно!\n\n";
    } else {
        std::cout << "✗ Ошибка в шифровании!\n\n";
    }
    
    std::cout << "Расшифрование... ";
    BigInt decrypted = grasshopperDeCode(ciphertext, key);
    std::cout << "Готово\n";
    std::cout << "Расшифрованный текст: " << decrypted.str(Base::HEX) << "\n";
    
    if (decrypted == plaintext) {
        std::cout << "✓ Расшифрование успешно!\n\n";
    } else {
        std::cout << "✗ Ошибка в расшифровании!\n\n";
    }
}
int main() {
    #ifdef _WIN32
        SetConsoleOutputCP(CP_UTF8);
    #endif
    testGrasshopper();
    
    return 0;
}