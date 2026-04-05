CXX = g++

ifeq ($(PORTABLE),1)
    ARCH_FLAGS = -mtune=generic
else
    ARCH_FLAGS = -march=native -mtune=native -mssse3
endif

# Removido -fpermissive conforme plano de robustez
CXXFLAGS = -O3 $(ARCH_FLAGS) -funroll-loops -Wall -Wextra -fpermissive
INCLUDES = -I../../libs/libsecp256k1/include -I../../libs/libsecp256k1/src -I../../libs
LIBS = -lgmp -lpthread

TARGET = modo-kangaroo
SRC = kangaroo.cpp ../../libs/util.c \
      ../../libs/base58/base58.c \
      ../../libs/rmd160/rmd160.c \
      ../../libs/hash/sha256.cpp \
      ../../libs/hash/ripemd160.cpp

default: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: default clean
