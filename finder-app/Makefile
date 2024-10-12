# Makefile


CFLAGS := -Wall -Werror


ifeq (${CROSS_COMPILE},)
	CROSS_COMPILE :=
endif

CC := ${CROSS_COMPILE}gcc


all: writer


writer: writer.c

	$(CC) $(CFLAGS) -c writer.c
	$(CC) $(CFLAGS) writer.o -o writer

clean:
	rm *.o writer
