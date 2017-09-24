OBJS = $(wildcard src/*.c)

CC = clang

LFLAGS = 

CFLAGS = -Wall

BIN = enigma

all : $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(BIN) $(LFLAGS)
