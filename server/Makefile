# Makefile


CFLAGS := -Wall -Werror


ifeq (${CROSS_COMPILE},)
        CROSS_COMPILE :=
endif

CC := ${CROSS_COMPILE}gcc


all: aesdsocket


aesdsocket: aesdsocket.c

	$(CC) $(CFLAGS) -c aesdsocket.c
	$(CC) $(CFLAGS) aesdsocket.o -o aesdsocket

clean:
	rm *.o aesdsocket
