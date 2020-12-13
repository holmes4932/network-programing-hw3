SHELL = /bin/bash
CC = gcc
CFLAGS = -lpcap
SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, $(SRC))

all: ${EXE}

%:	%.c
	${CC} ${CFLAGS} $@.c -o $@ 

clean:
	rm ${EXE}

