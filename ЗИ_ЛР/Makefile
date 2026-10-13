# Сборка криптографического слоя.
#
#   make              -> crypto_cli (то, что вызывает веб-приложение)
#   make test         -> crypto_cli + самопроверка по векторам ГОСТ
#   make labs         -> три лабораторных стенда по отдельности
#   make clean
#
# На Windows под MinGW нужно добавить линковку с bcrypt:
#   make LDLIBS=-lbcrypt
# (rsa_bigint.cpp берёт случайные байты из BCryptGenRandom на Windows
#  и из /dev/urandom на Linux.)

CXX      ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall
LDLIBS   ?=

# Ядро: длинная арифметика и три примитива ГОСТ плюс режим CTR.
CORE = BigInt.cpp grasshopper.cpp stribog.cpp rsa_bigint.cpp kuz_ctr.cpp

.PHONY: all test labs clean

all: crypto_cli

crypto_cli: crypto_cli.cpp $(CORE) BigInt.h cryptography.h kuz_ctr.h modMath.h
	$(CXX) $(CXXFLAGS) -o $@ crypto_cli.cpp $(CORE) $(LDLIBS)

test: crypto_cli
	./crypto_cli selftest
	./test_cli.sh

# Лабораторные стенды остаются как были: каждый со своим main().
labs: grasshopper_app stribog_app rsa_app

grasshopper_app: grasshopper_main.cpp $(CORE)
	$(CXX) $(CXXFLAGS) -o $@ grasshopper_main.cpp $(CORE) $(LDLIBS)

stribog_app: stribog_main.cpp $(CORE)
	$(CXX) $(CXXFLAGS) -o $@ stribog_main.cpp $(CORE) $(LDLIBS)

rsa_app: rsa_main.cpp $(CORE)
	$(CXX) $(CXXFLAGS) -o $@ rsa_main.cpp $(CORE) $(LDLIBS)

clean:
	rm -f crypto_cli grasshopper_app stribog_app rsa_app probe *.o
