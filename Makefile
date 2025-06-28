CC=gcc
CFLAGS=-Wall -std=c99
LDFLAGS=-lpcap

all: sniff

sniff: main.o parser.o
	$(CC) -o $@ $^ $(LDFLAGS)

main.o: main.c parser.h
parser.o: parser.c parser.h

clean:
	rm -f *.o sniff