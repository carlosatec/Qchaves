CXX = g++
CXXFLAGS = -O3 -march=westmere -funroll-loops -Wall -Wextra -fpermissive
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
