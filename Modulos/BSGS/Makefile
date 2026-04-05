CXX = g++
CC = gcc
OLEVEL = -O3

COMMON_FLAGS = -I../../libs -m64 -Wall -Wextra -Wno-deprecated-copy -Wno-unused-parameter $(OLEVEL) -ftree-vectorize -flto

ifeq ($(PORTABLE),1)
    ARCH_FLAGS = -mtune=generic
else
    ARCH_FLAGS = -march=native -mtune=native -mssse3
endif

CXXFLAGS = $(COMMON_FLAGS) $(ARCH_FLAGS)
CFLAGS = $(COMMON_FLAGS) $(ARCH_FLAGS)
CFLAGS := $(subst -Wno-deprecated-copy,,$(CFLAGS))

TARGET = modo-bsgs

OBJS = base58.o rmd160.o sha3.o keccak.o xxhash.o util.o Int.o Point.o SECP256K1.o IntMod.o Random.o IntGroup.o ripemd160.o sha256.o ripemd160_sse.o sha256_sse.o cuckoo.o

default: $(TARGET)

cuckoo.o: ../../libs/cuckoo/cuckoo.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

base58.o: ../../libs/base58/base58.c
	$(CC) $(CFLAGS) -c $< -o $@

rmd160.o: ../../libs/rmd160/rmd160.c
	$(CC) $(CFLAGS) -c $< -o $@

sha3.o: ../../libs/sha3/sha3.c
	$(CXX) $(CXXFLAGS) -c $< -o $@

keccak.o: ../../libs/sha3/keccak.c
	$(CXX) $(CXXFLAGS) -c $< -o $@

xxhash.o: ../../libs/xxhash/xxhash.c
	$(CC) $(CFLAGS) -c $< -o $@

util.o: ../../libs/util.c
	$(CXX) $(CXXFLAGS) -c $< -o $@

Int.o: ../../libs/secp256k1/Int.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

Point.o: ../../libs/secp256k1/Point.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

SECP256K1.o: ../../libs/secp256k1/SECP256K1.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

IntMod.o: ../../libs/secp256k1/IntMod.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

Random.o: ../../libs/secp256k1/Random.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

IntGroup.o: ../../libs/secp256k1/IntGroup.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

ripemd160.o: ../../libs/hash/ripemd160.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

sha256.o: ../../libs/hash/sha256.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

ripemd160_sse.o: ../../libs/hash/ripemd160_sse.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

sha256_sse.o: ../../libs/hash/sha256_sse.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TARGET): bsgs.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ -lm -lpthread
	rm -f *.o

clean:
	rm -f $(TARGET) *.o
