#!/usr/bin/env bash
# Сборка crypto_cli. Запускать в Linux/WSL: make тут не нужен, если его нет.
set -e
cd "$(dirname "$0")"
g++ -O2 -std=c++17 -Wall -o crypto_cli \
    crypto_cli.cpp BigInt.cpp grasshopper.cpp stribog.cpp rsa_bigint.cpp kuz_ctr.cpp
echo "собрано: $(pwd)/crypto_cli"
