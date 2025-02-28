CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -O3 

TARGET = fuzzer
SRC = src/main.c src/utils.c
HEADER = src/constants.h src/utils.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) $(HEADER)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET) *.tar success_*.tar  