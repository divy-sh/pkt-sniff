CC=gcc
CFLAGS=-Wall -std=c99
LDFLAGS=-lpcap

all: sniff

sniff: main.o parser.o utils.o
	$(CC) -o $@ $^ $(LDFLAGS)

main.o: main.c parser.h utils.h
parser.o: parser.c parser.h
utils.o: utils.c utils.h

clean:
	rm -f *.o sniff