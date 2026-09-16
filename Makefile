CC=gcc
CFLAGS=-O2 -Wall

all: sldp

sldp: sldp.c
	$(CC) $(CFLAGS) sldp.c -o sldp

clean:
	rm -f sldp
