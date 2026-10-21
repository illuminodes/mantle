all: module.a

CXXFLAGS += -Wall -Wextra -fsanitize=address,fuzzer -std=c++20 -I ../../include
RUST_LIB_PATH := ./mantle_lib/target/release/libmantle_bitcoinfuzz.a

$(RUST_LIB_PATH):
	cd mantle_lib && cargo build --release

cargo: $(RUST_LIB_PATH)

module.a: module.o $(RUST_LIB_PATH)
	bash ../../merge.sh module.a $(RUST_LIB_PATH) module.o
	ranlib module.a

module.o: module.cpp module.h
	$(CXX) $(CXXFLAGS) -I . -fPIC -c module.cpp -o module.o

format:
	clang-format -i ./module.cpp ./module.h ./mantle_lib/mantle_lib.h
	cd mantle_lib && cargo fmt

check-format:
	clang-format -Werror --fail-on-incomplete-format -n ./module.cpp ./module.h ./mantle_lib/mantle_lib.h
	cd mantle_lib && cargo fmt --check

clean:
	rm -rf *.o module.a
	cd mantle_lib && cargo clean

.PHONY: all cargo clean format check-format $(RUST_LIB_PATH)
