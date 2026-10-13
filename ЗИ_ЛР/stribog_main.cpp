#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
#include <iostream>
#include "BigInt.h"
#include "cryptography.h"

void testStribogGOST() {
    std::cout << "=== Тестирование Стрибог по ГОСТ Р 34.11-2018 ===\n\n";

    // Тест A.2.1 - Сообщение M1 для 512-битного хеша
    std::cout << "A.2.1 Тест для 512-битного хеша:\n";
    std::string hexMessage1 = "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130";
    
    BigInt message1(hexMessage1.c_str());
    BigInt hash512 = stribog(message1, 512);
    
    std::string expected512 = "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b";
    
    std::cout << "Вход: " << hexMessage1 << "\n";
    std::cout << "Получено: " << hash512.str(Base::HEX) << "\n";
    std::cout << "Ожидалось: " << expected512 << "\n";
    
    // Нормализуем вывод - добавляем ведущие нули если нужно
    std::string obtained512 = hash512.str(Base::HEX);
    while (obtained512.length() < expected512.length()) {
        obtained512 = "0" + obtained512;
    }
    
    std::cout << "Результат: " << (obtained512 == expected512 ? "✓ ПРОЙДЕН" : "✗ ОШИБКА") << "\n\n";

    // Тест A.2.3 - Сообщение M1 для 256-битного хеша
    std::cout << "A.2.3 Тест для 256-битного хеша:\n";
    BigInt hash256 = stribog(message1, 256);
    
    std::string expected256 = "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d";
    
    std::cout << "Вход: " << hexMessage1 << "\n";
    std::cout << "Получено: " << hash256.str(Base::HEX) << "\n";
    std::cout << "Ожидалось: " << expected256 << "\n";
    
    // Нормализуем вывод для 256-битного хеша
    std::string obtained256 = hash256.str(Base::HEX);
    while (obtained256.length() < expected256.length()) {
        obtained256 = "0" + obtained256;
    }
    
    std::cout << "Результат: " << (obtained256 == expected256 ? "✓ ПРОЙДЕН" : "✗ ОШИБКА") << "\n\n";
}

int main() {
    #ifdef _WIN32
        SetConsoleOutputCP(CP_UTF8);
    #endif
    testStribogGOST();
    return 0;
}