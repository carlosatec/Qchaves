default:
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -flto -c ../../libs/cuckoo/cuckoo.cpp -o cuckoo.o
	gcc -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-unused-parameter -Ofast -ftree-vectorize -c ../../libs/base58/base58.c -o base58.o
	gcc -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c ../../libs/rmd160/rmd160.c -o rmd160.o
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c ../../libs/sha3/sha3.c -o sha3.o
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c ../../libs/sha3/keccak.c -o keccak.o
	gcc -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c ../../libs/xxhash/xxhash.c -o xxhash.o
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c ../../libs/util.c -o util.o
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c ../../libs/secp256k1/Int.cpp -o Int.o
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c ../../libs/secp256k1/Point.cpp -o Point.o
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c ../../libs/secp256k1/SECP256K1.cpp -o SECP256K1.o
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c ../../libs/secp256k1/IntMod.cpp -o IntMod.o
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -flto -c ../../libs/secp256k1/Random.cpp -o Random.o
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -flto -c ../../libs/secp256k1/IntGroup.cpp -o IntGroup.o
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -o ripemd160.o -ftree-vectorize -flto -c ../../libs/hash/ripemd160.cpp
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -o sha256.o -ftree-vectorize -flto -c ../../libs/hash/sha256.cpp
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -o ripemd160_sse.o -ftree-vectorize -flto -c ../../libs/hash/ripemd160_sse.cpp
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -o sha256_sse.o -ftree-vectorize -flto -c ../../libs/hash/sha256_sse.cpp
	g++ -I../../libs -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -o modo-address address.cpp base58.o rmd160.o ripemd160.o ripemd160_sse.o sha256.o sha256_sse.o cuckoo.o xxhash.o util.o Int.o Point.o SECP256K1.o IntMod.o Random.o IntGroup.o sha3.o keccak.o -lm -lpthread
	rm -f *.o
clean:
	rm -f modo-address *.o
