SHELL = /bin/bash
CC = gcc
CFLAGS =
SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, $(SRC))

all: ${EXE}

%:	%.c
	${CC} ${CFLAGS} $@.c -o $@ -lpcap

clean:
	rm ${EXE}

