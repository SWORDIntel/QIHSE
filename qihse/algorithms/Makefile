# QIHSE Algorithms Makefile

CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -I.. -I../core -fPIC -O2 -g
LDFLAGS = -lm

# Source files
SRCS = qihse_rff.c qihse_superposition.c qihse_amplification.c qihse_dimensions.c qihse_verification.c
HEADERS = qihse_rff.h qihse_superposition.h qihse_amplification.h qihse_dimensions.h qihse_verification.h

# Object files
OBJS = $(SRCS:.c=.o)

# Test programs
TEST_RFF = test_rff
TEST_SUPERPOSITION = test_superposition
TEST_AMPLIFICATION = test_amplification
TEST_DIMENSIONS = test_dimensions
TEST_VERIFICATION = test_verification

# All test programs
TESTS = $(TEST_RFF) $(TEST_SUPERPOSITION) $(TEST_AMPLIFICATION) $(TEST_DIMENSIONS) $(TEST_VERIFICATION)

.PHONY: all clean test check

all: $(TESTS)

# Build object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Test programs
$(TEST_RFF): test_rff.c qihse_rff.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_SUPERPOSITION): test_superposition.c qihse_superposition.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_AMPLIFICATION): test_amplification.c qihse_amplification.o qihse_superposition.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_DIMENSIONS): test_dimensions.c qihse_dimensions.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_VERIFICATION): test_verification.c qihse_verification.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Test targets
test_rff: $(TEST_RFF)
	./$(TEST_RFF)

test_superposition: $(TEST_SUPERPOSITION)
	./$(TEST_SUPERPOSITION)

test_amplification: $(TEST_AMPLIFICATION)
	./$(TEST_AMPLIFICATION)

test_dimensions: $(TEST_DIMENSIONS)
	./$(TEST_DIMENSIONS)

test_verification: $(TEST_VERIFICATION)
	./$(TEST_VERIFICATION)

# Run all tests
test: $(TESTS)
	@echo "Running QIHSE algorithm tests..."
	@./$(TEST_RFF) && echo "RFF tests passed" || echo "RFF tests failed"
	@./$(TEST_SUPERPOSITION) && echo "Superposition tests passed" || echo "Superposition tests failed"
	@./$(TEST_AMPLIFICATION) && echo "Amplification tests passed" || echo "Amplification tests failed"
	@./$(TEST_DIMENSIONS) && echo "Dimensions tests passed" || echo "Dimensions tests failed"
	@./$(TEST_VERIFICATION) && echo "Verification tests passed" || echo "Verification tests failed"
	@echo "Algorithm tests completed"

# Compilation check
check: $(SRCS) $(HEADERS)
	@echo "Checking compilation..."
	@$(CC) $(CFLAGS) -fsyntax-only $(SRCS) && echo "Compilation check passed" || echo "Compilation check failed"

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TESTS) *.o

# Dependencies
qihse_rff.o: qihse_rff.h
qihse_superposition.o: qihse_superposition.h
qihse_amplification.o: qihse_amplification.h qihse_superposition.h
qihse_dimensions.o: qihse_dimensions.h
qihse_verification.o: qihse_verification.h
