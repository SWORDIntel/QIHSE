CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror
LDFLAGS ?= -ljansson

TARGET = supermemory-bridge
SRC = supermemory-bridge.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean
