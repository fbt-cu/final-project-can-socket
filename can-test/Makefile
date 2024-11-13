# Makefile
# To build and clean the can-test utility

#If CROSS_COMPILE is defined only as aarch64-none-linux-gnu- do cross compilation else do native compilation

CC ?= $(CROSS_COMPILE)gcc

#Target executable can_receive
TARGET?=can-test

OBJS = $(SRC:.c=.o)
SRC  = can-test.c
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