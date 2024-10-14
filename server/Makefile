# Makefile
# To build and clean the aesdsocket utility
# Author: Induja Narayanan <Induja.Narayanan@colorado.edu>

#If CROSS_COMPILE is defined only as aarch64-none-linux-gnu- do cross compilation else do native compilation

CC ?= $(CROSS_COMPILE)gcc

#Target executable aesdsocket utility
TARGET?=aesdsocket

OBJS = $(SRC:.c=.o)
SRC  = aesdsocket.c
CFLAGS ?= -Werror -Wall -Wunused -Wunused-variable -Wextra
LDFLAGS ?= -lpthread -lrt

all:$(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(INCLUDES) -o $(TARGET) $(OBJS) 
#$(CC) $(CFLAGS) $^-o $@ $(INCLUDES) $(LDFLAGS)

%.o: %.c
	$(CC) -c $< -o $@
clean: 
	rm -f $(OBJS) $(TARGET)