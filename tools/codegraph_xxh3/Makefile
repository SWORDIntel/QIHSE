CC ?= cc
AR ?= ar
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -Werror
CPPFLAGS ?=
LDFLAGS ?=
BUILD ?= build
PORTABLE ?= 0
INCLUDES = -Iinclude -Isrc -Ivendor
MACHINE := $(shell $(CC) -dumpmachine)
X86 := $(if $(findstring x86_64,$(MACHINE)),1,0)
BASE_ISA =
MULTI =
BACKENDS = $(BUILD)/scalar.o
ifeq ($(X86),1)
BASE_ISA = -march=x86-64 -mtune=generic
ifeq ($(PORTABLE),0)
MULTI = -DQX3_X86_MULTI
BACKENDS += $(BUILD)/sse2.o $(BUILD)/avx2.o $(BUILD)/avx512.o
endif
endif
CORE = $(BUILD)/qihse_xxh3.o $(BACKENDS)
HEADERS = include/qihse_xxh3.h src/internal.h vendor/xxhash.h
.PHONY: all test benchmark sanitize clean FORCE
all: $(BUILD)/libqihse_xxh3.a $(BUILD)/libqihse_xxh3.so $(BUILD)/qx3sum $(BUILD)/test $(BUILD)/example
$(BUILD):
	mkdir -p $@
# Changing compiler/options rebuilds objects, instead of silently reusing old tuning.
$(BUILD)/config: FORCE | $(BUILD)
	@printf '%s\n' '$(CC)|$(CPPFLAGS)|$(CFLAGS)|$(LDFLAGS)|$(PORTABLE)|$(BASE_ISA)' > $@.tmp
	@cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@
$(BUILD)/qihse_xxh3.o: src/qihse_xxh3.c $(HEADERS) $(BUILD)/config
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(BASE_ISA) $(MULTI) -fPIC -c $< -o $@
$(BUILD)/scalar.o: src/backend.c $(HEADERS) $(BUILD)/config
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(BASE_ISA) -fPIC -DQX3_VECTOR=0 -DQX3_SYMBOL=qx3_backend_scalar -DQX3_NAME='"scalar"' -c $< -o $@
$(BUILD)/sse2.o: src/backend.c $(HEADERS) $(BUILD)/config
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(BASE_ISA) -msse2 -fPIC -DQX3_VECTOR=1 -DQX3_SYMBOL=qx3_backend_sse2 -DQX3_NAME='"sse2"' -c $< -o $@
$(BUILD)/avx2.o: src/backend.c $(HEADERS) $(BUILD)/config
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(BASE_ISA) -mavx2 -fPIC -DQX3_VECTOR=2 -DQX3_SYMBOL=qx3_backend_avx2 -DQX3_NAME='"avx2"' -c $< -o $@
$(BUILD)/avx512.o: src/backend.c $(HEADERS) $(BUILD)/config
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(BASE_ISA) -mavx512f -mavx512bw -mavx512dq -fPIC -DQX3_VECTOR=3 -DQX3_SYMBOL=qx3_backend_avx512 -DQX3_NAME='"avx512"' -c $< -o $@
$(BUILD)/libqihse_xxh3.a: $(CORE)
	rm -f $@
	$(AR) rcs $@ $^
$(BUILD)/libqihse_xxh3.so: $(CORE)
	$(CC) -shared $(LDFLAGS) $^ -o $@
$(BUILD)/qx3sum: tools/qx3sum.c $(HEADERS) $(BUILD)/libqihse_xxh3.a
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(BASE_ISA) $< $(BUILD)/libqihse_xxh3.a $(LDFLAGS) -o $@
$(BUILD)/example: examples/hash.c include/qihse_xxh3_inline.h $(BUILD)/libqihse_xxh3.a
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(BASE_ISA) $< $(BUILD)/libqihse_xxh3.a $(LDFLAGS) -o $@
$(BUILD)/test: tests/test.c include/qihse_xxh3_inline.h $(HEADERS) $(BUILD)/libqihse_xxh3.a
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(BASE_ISA) $< $(BUILD)/libqihse_xxh3.a $(LDFLAGS) -pthread -o $@
test: all
	./$(BUILD)/test
	./$(BUILD)/example
	python3 tests/test_cli.py ./$(BUILD)/qx3sum
$(BUILD)/system_ref.o: bench/system_ref.c include/qihse_xxh3.h $(BUILD)/config
	$(CC) $(CPPFLAGS) -Iinclude $(CFLAGS) $(BASE_ISA) -c $< -o $@
$(BUILD)/bench: bench/bench.c include/qihse_xxh3_inline.h $(BUILD)/system_ref.o $(BUILD)/libqihse_xxh3.a
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(BASE_ISA) -Wno-deprecated-declarations $< $(BUILD)/system_ref.o $(BUILD)/libqihse_xxh3.a $(LDFLAGS) -lxxhash -lcrypto -o $@
benchmark: $(BUILD)/bench
	python3 bench/run.py --binary ./$(BUILD)/bench --corpus corpus --out results/local.json
sanitize:
	$(MAKE) BUILD=build-sanitize CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address,undefined' all
	ASAN_OPTIONS=detect_leaks=0 ./build-sanitize/test
	ASAN_OPTIONS=detect_leaks=0 python3 tests/test_cli.py ./build-sanitize/qx3sum
clean:
	rm -rf build build-sanitize build-clang build-portable
$(BUILD)/test-oracle: tests/test.c include/qihse_xxh3_inline.h $(BUILD)/system_ref.o $(BUILD)/libqihse_xxh3.a
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(BASE_ISA) -DQX3_SYSTEM_ORACLE $< $(BUILD)/system_ref.o $(BUILD)/libqihse_xxh3.a $(LDFLAGS) -pthread -lxxhash -o $@
.PHONY: test-oracle
test-oracle: $(BUILD)/test-oracle
	./$(BUILD)/test-oracle
