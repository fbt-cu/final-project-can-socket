# Makefile
# To build and clean the can-socket application
# Author: Fernando Becerra Tanaka <fernando.becerratnaka@colorado.edu>
# Based on the work of Induja Narayanan <Induja.Narayanan@colorado.edu>

#If CROSS_COMPILE is defined only as aarch64-none-linux-gnu- do cross compilation else do native compilation

CC ?= $(CROSS_COMPILE)gcc

#Target executable can-socket application
TARGET?=can-socket

OBJS = $(SRC:.c=.o)
SRC  = can-socket.c
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