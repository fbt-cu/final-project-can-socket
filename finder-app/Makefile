# Makefile

make: writer.c
ifeq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
	aarch64-none-linux-gnu-gcc -g -Wall -c  writer.c -o writer.o
	aarch64-none-linux-gnu-gcc -g -Wall -I/ writer.o -o writer.elf
else
	gcc -g -Wall -c  writer.c -o writer.o
	gcc -g -Wall -I/ writer.o -o writer
endif

clean: 
	rm -f writer *.o *.elf *.map

